local silly = require "silly"
local task = require "silly.task"
local time = require "silly.time"
local logger = require "silly.logger"
local tcp = require "silly.net.tcp"
local env = require "silly.env"
local grpc = require "silly.net.grpc"
local protoc = require "protoc"
local cipher = require "silly.crypto.cipher"
local base64 = require "silly.encoding.base64"
local crypto = require "silly.crypto.utils"

env.load("./common.conf")

-- Get encryption key
local crypt_key = assert(env.get("key"), "crypt key required")
assert(#crypt_key == 16, "crypt key must be 16 bytes for AES-128")

-- Load protobuf schema
local p = protoc:new()
local ok = p:loadfile("tunnel.proto")
assert(ok, "failed to load tunnel.proto")
local proto = p.loaded["tunnel.proto"]

-- Create gRPC client
local serveraddr = assert(env.get("server"), "server address required")
logger.infof("[client] server addr: %s", serveraddr)
local targets = {}
for i = 1, 16 do
	targets[i] = serveraddr
end
local grpc_conn = grpc.newclient { targets = targets }
assert(grpc_conn, "failed to create grpc client")

local service = grpc.newservice(grpc_conn, proto, "Tunnel")
assert(service, "failed to create tunnel service")

logger.infof("[client] connected to grpc server: %s", serveraddr)

-- Encrypt target domain with random IV
local function encrypt_target(target)
	local iv = crypto.randomkey(16)  -- Random 16-byte IV
	local plaintext = "tunnel://" .. target
	local enc = cipher.encryptor("aes-128-cbc", crypt_key, iv)
	local ciphertext = enc:final(plaintext)
	-- Return: IV + ciphertext, base64 encoded
	return base64.encode(iv .. ciphertext)
end

-- Create tunnel for a connection
local function create_tunnel(conn, domain, port, firstdata)
	local target = string.format("%s:%d", domain, port)
	-- Open bidirectional stream
	local stream<close>, err = service:Connect()
	if not stream then
		logger.errorf("[client] failed to create stream: %s", err)
		conn:close()
		return
	end
	logger.infof("[client] creating tunnel target=%s", target)

	-- Encrypt target domain
	local encrypted_target = encrypt_target(target)

	-- Send first request with encrypted domain
	local pad_len = math.random(0, 512)
	local pad = string.rep(string.char(math.random(0, 255)), pad_len)
	local ok, err = stream:write({
		domain = encrypted_target,
		data = firstdata or "",
		pad = pad,
	})
	if not ok then
		logger.errorf("[client] failed to write first request: %s", err)
		conn:close()
		return
	end
	-- Fork task to read from local conn and write to stream
	task.fork(function()
		while true do
			local data, err = conn:read(1)
			if err then
				stream:write({data = "", pad = pad})
				logger.info("[client] read conn failed:", err)
				conn:close()
				return
			end
			local more = conn:read(conn:unreadbytes())
			if more and more ~= "" then
				data = data .. more
			end
			local pad_len = math.random(0, 512)
			local pad = string.rep(string.char(math.random(0, 255)), pad_len)

			local ok, err = stream:write({data = data, pad = pad})
			if not ok then
				logger.infof("[client] write stream failed: %s", err)
				conn:close()
				return
			end
		end
	end)
	-- Current task: read from stream and write to conn
	while true do
		local resp = stream:read()
		if not resp then
			logger.info("[client] read stream closed:", stream.message)
			conn:close()
			return
		end
		local data = resp.data
		if not data or #data == 0 then
			conn:close()
			return
		end
		local ok, err = conn:write(resp.data)
		if not ok then
			logger.info("[client] write conn failed:", err)
			conn:close()
			return
		end
	end
end

-- SOCKS5 authentication
local function socks5_auth(conn)
	local str = conn:read(3)
	if not str then
		return false
	end

	local ver, nr, method = string.unpack("<I1I1I1", str)
	if ver ~= 0x05 then
		logger.errorf("[client] invalid socks version: %d", ver)
		return false
	end

	local noauth = (method == 0x0)
	if not noauth and nr > 1 then
		nr = nr - 1
		str = conn:read(nr)
		if not str then
			return false
		end
		for i = 1, #str do
			if str:byte(i) == 0x0 then
				noauth = true
				break
			end
		end
	end
	if not noauth then
		logger.error("[client] socks5 auth not supported")
		return false
	end

	conn:write(string.pack("<I1I1", 0x05, 0x00))
	return true
end

-- SOCKS5 connect request
local function socks5_connect(conn)
	local str = conn:read(4)
	if not str then
		return nil, nil
	end

	local ver, cmd, rsv, atyp = string.unpack("<I1I1I1I1", str)
	if cmd ~= 1 then  -- CONNECT
		logger.errorf("[client] unsupported socks command: %d", cmd)
		return nil, nil
	end

	local domain
	if atyp == 3 then  -- Domain name
		str = conn:read(1)
		if not str then
			return nil, nil
		end
		local len = str:byte(1)
		domain = conn:read(len)
	elseif atyp == 1 then  -- IPv4
		local ip_bytes = conn:read(4)
		if not ip_bytes then
			return nil, nil
		end
		domain = string.format("%d.%d.%d.%d", ip_bytes:byte(1, 4))
	else
		logger.errorf("[client] unsupported address type: %d", atyp)
		return nil, nil
	end

	str = conn:read(2)
	if not str then
		return nil, nil
	end
	local port = string.unpack(">I2", str)

	-- Send SOCKS5 success response
	conn:write("\x05\x00\x00\x01\x00\x00\x00\x00\xe9\xc7")

	return domain, port
end

-- SOCKS5 proxy handler
local function socks5_handler(conn)
	logger.info("[client] socks5 connection")

	if not socks5_auth(conn) then
		conn:close()
		return
	end

	local domain, port = socks5_connect(conn)
	if not domain then
		conn:close()
		return
	end

	logger.infof("[client] socks5 target: %s:%d", domain, port)
	create_tunnel(conn, domain, port)
end

-- TLS SNI parser
local function parse_sni(conn)
	local head = conn:read(5)
	if not head then
		return nil, nil
	end

	local typ, major, minor, len = string.unpack(">I1I1I1I2", head)
	if typ ~= 22 then  -- Handshake
		logger.errorf("[client] not a tls handshake: type=%s", typ)
		return nil, nil
	end

	local body = conn:read(len)
	if not body then
		return nil, nil
	end

	local offset = 1
	local msgtype = string.unpack(">I1", body, offset)
	if msgtype ~= 1 then  -- ClientHello
		return nil, nil
	end

	offset = offset + 4 + 2 + 4 + 28  -- msgtype, msglen, client ver, random
	local session_len = string.unpack(">I1", body, offset)
	offset = offset + session_len + 1

	local cipher_len = string.unpack(">I2", body, offset)
	offset = offset + cipher_len + 2

	local compress_len = string.unpack(">I1", body, offset)
	offset = offset + compress_len + 1

	if offset >= len then
		return nil, nil
	end

	-- Extensions
	local ext_len = string.unpack(">I2", body, offset)
	offset = offset + 2

	while ext_len > 0 do
		local t, l = string.unpack(">I2I2", body, offset)
		offset = offset + 4
		ext_len = ext_len - 4

		if t == 0x0 then  -- server_name extension
			while l > 0 do
				local list_len = string.unpack(">I2", body, offset)
				offset = offset + 2
				l = l - 2

				while list_len > 0 do
					local nt, nl = string.unpack(">I1I2", body, offset)
					offset = offset + 3
					list_len = list_len - 3

					if nt == 0 then  -- host_name
						local domain = string.sub(body, offset, offset + nl - 1)
						return domain, head .. body
					end

					offset = offset + nl
					list_len = list_len - nl
				end
			end
		end

		offset = offset + l
		ext_len = ext_len - l
	end

	return nil, nil
end

-- SNI proxy handler
local function sni_handler(conn)
	logger.info("[client] sni connection")
	local domain, firstdata = parse_sni(conn)
	if not domain then
		logger.error("[client] failed to parse sni")
		conn:close()
		return
	end
	logger.infof("[client] sni domain: %s", domain)
	create_tunnel(conn, domain, 443, firstdata)
end

-- Start SOCKS5 proxy
tcp.listen {
	addr = env.get("socks5"),
	accept = function(conn)
		socks5_handler(conn)
	end
}

logger.infof("[client] socks5 proxy listening on %s", env.get("socks5"))

-- Start SNI proxy
tcp.listen {
	addr = "0.0.0.0:443",
	accept = function(conn)
		sni_handler(conn)
	end
}

logger.infof("[client] sni proxy listening on 0.0.0.0:443")

-- Fixed port proxy example (optional)
tcp.listen {
	addr = "0.0.0.0:9930",
	accept = function(conn)
		logger.info("[client] fixed proxy connection")
		create_tunnel(conn, "imap.gmail.com", 993)
	end
}

logger.infof("[client] fixed proxy listening on 0.0.0.0:9930 -> imap.gmail.com:993")
