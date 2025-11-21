local task = require "silly.task"
local logger = require "silly.logger"
local env = require "silly.env"
local tcp = require "silly.net.tcp"
local dns = require "silly.net.dns"
local grpc = require "silly.net.grpc"
local protoc = require "protoc"
local registrar = require "silly.net.grpc.registrar".new()
local cipher = require "silly.crypto.cipher"
local base64 = require "silly.encoding.base64"

env.load("common.conf")

-- Get encryption key
local crypt_key = assert(env.get("key"), "crypt key required")
assert(#crypt_key == 16, "crypt key must be 16 bytes for AES-128:" .. crypt_key)

-- Load protobuf schema
local p = protoc:new()
local ok = p:loadfile("tunnel.proto")
assert(ok, "failed to load tunnel.proto")
local proto = p.loaded["tunnel.proto"]

-- Decrypt and verify target domain
local function decrypt_target(encrypted_domain)
	-- Base64 decode
	local ok, decoded = pcall(base64.decode, encrypted_domain)
	if not ok or not decoded or #decoded < 32 then  -- At least IV(16) + 1 block(16)
		logger.errorf("[server] invalid encrypted domain: decode failed")
		return nil, "invalid encrypted domain"
	end

	-- Extract IV and ciphertext
	local iv = decoded:sub(1, 16)
	local ciphertext = decoded:sub(17)

	-- Decrypt
	local dec = cipher.decryptor("aes-128-cbc", crypt_key, iv)
	local ok, plaintext = pcall(function()
		return dec:final(ciphertext)
	end)

	if not ok or not plaintext then
		logger.errorf("[server] decryption failed")
		return nil, "decryption failed"
	end

	-- Verify tunnel:// prefix
	if not plaintext:match("^tunnel://") then
		logger.errorf("[server] invalid target prefix: %s", plaintext:sub(1, 20))
		return nil, "invalid target prefix"
	end

	-- Remove tunnel:// prefix
	local target = plaintext:sub(10)  -- Remove "tunnel://"
	logger.infof("[server] decrypted target: %s", target)
	return target, nil
end

-- TCP connect helper
local function tcp_connect(addr)
	local domain, port = string.match(addr, "^([^:]+):(%d+)$")
	if not domain or not port then
		logger.errorf("[server] invalid address format: %s", addr)
		return nil
	end

	local ip = domain
	if dns.isname(domain) then
		ip = dns.lookup(domain, dns.A)
		if not ip then
			logger.errorf("[server] dns lookup failed: %s", domain)
			return nil
		end
	end

	local target = string.format("%s:%s", ip, port)
	local conn, err = tcp.connect(target)
	if not conn then
		logger.errorf("[server] tcp connect failed: %s err=%s", target, err)
		return nil
	end

	conn:limit(1 * 1024 * 1024)
	logger.infof("[server] connected to %s", target)
	return conn
end

-- Tunnel service implementation
registrar:register(proto, "Tunnel", {
	Connect = function(stream)
		-- Read first request, must have domain
		local req = stream:read()
		if not req then
			logger.error("[server] failed to read first request")
			return
		end
		if not req.domain or req.domain == "" then
			logger.error("[server] first request must have domain")
			return {code = 3, message = "domain required"}  -- INVALID_ARGUMENT
		end

		-- Decrypt and verify target
		local target, err = decrypt_target(req.domain)
		if not target then
			logger.errorf("[server] authentication failed: %s", err)
			return {code = 16, message = "unauthenticated"}  -- UNAUTHENTICATED
		end

		-- Connect to target
		local conn = tcp_connect(target)
		if not conn then
			logger.errorf("[server] failed to connect to %s", target)
			return {code = 14, message = "connect failed"}  -- UNAVAILABLE
		end
		logger.infof("[server] stream connected to %s", target)
		-- Fork task to read from conn and write to stream
		task.fork(function()
			while true do
				local data, err = conn:read(1)
				if err then
					-- Send close signal to client
					local pad_len = math.random(0, 512)
					local pad = string.rep(string.char(math.random(0, 255)), pad_len)
					stream:write({data = "", pad = pad})
					logger.infof("[server] read conn err:%s", err)
					conn:close()
					return
				end

				local more = conn:read(conn:unreadbytes())
				if more and more ~= "" then
					data = data .. more
				end
				-- Add random padding
				local pad_len = math.random(0, 512)
				local pad = string.rep(string.char(math.random(0, 255)), pad_len)
				local ok, err = stream:write({data = data, pad = pad})
				if not ok then
					logger.infof("[server] write stream failed: %s", err)
					conn:close()
					return
				end
			end
		end)
		-- Write initial data if present
		if req.data and #req.data > 0 then
			conn:write(req.data)
		end
		-- Current task: read from stream and write to conn
		while true do
			req = stream:read()
			if not req then
				logger.info("[server] read stream closed")
				conn:close()
				return
			end
			local data = req.data
			if not data or #data == 0 then
				logger.info("[server] remote conn closed")
				conn:close()
				return
			end
			local ok, err = conn:write(req.data)
			if not ok then
				logger.info("[server] write conn failed:", err)
				conn:close()
				return
			end
		end
	end
})

-- Start gRPC server
local server = grpc.listen {
	addr = "0.0.0.0:443",
	registrar = registrar,
}

assert(server, "failed to start grpc server")
logger.infof("[server] grpc tunnel server started on 0.0.0.0:443")
