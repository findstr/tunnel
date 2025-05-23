local core = require "core"
local dns = require "core.dns"
local logger = require "core.logger"
local env = require "core.env"
local socket = require "core.net.tcp"
local http = require "core.http"
local websocket = require "core.websocket"
local prometheus = require "core.metrics.prometheus"

local assert = assert

env.load("common.conf")

local packet = require "packet"

local function tcp_connect(addr)
	local ip
	local domain, port = string.match(addr, "^([^:]+):(%d+)$")
	if dns.isname(domain) then
		ip = dns.lookup(domain, dns.A)
		if not ip then
			logger.error("dns lookup failed", domain)
			return nil, nil, "dns lookup failed"
		end
	else
		ip = domain
	end
	local addr = string.format("%s:%d", ip, port)
	local fd = socket.connect(addr)
	if not fd then
		logger.error("tcp connect failed", addr)
		return
	end
	logger.infof("tcp_connect addr:%s fd:%s", addr, fd)
	return fd
end

---@param tunnel core.websocket.socket
local function control(tunnel)
	local uuid_to_fd = {}
	local cmd, uuid, key = packet.readpacket(tunnel)
	if not cmd then
		logger.info("control", tunnel.fd, "read err:", cmd)
		return
	end
	assert(cmd == packet.AUTH, "need auth")
	if key ~= env.get("crypt") then
		logger.error("auth failed", key)
		return
	end
	packet.writehello(tunnel, tunnel.fd << 32)
	while true do
		local cmd, uuid, ud = packet.readpacket(tunnel)
		if not cmd then
			logger.info("control", tunnel.fd, "read err:", ud)
			return
		end
		assert(uuid, "need uuid")
		if cmd == packet.OPEN then
			local addr = ud
			local fd = tcp_connect(addr)
			if not fd then
				packet.writeclose(tunnel, uuid)
				return
			end
			socket.limit(fd, 1 * 1024 * 1024)
			uuid_to_fd[uuid] = fd
			uuid_to_fd[fd] = uuid
			core.fork(function()
				packet.fromraw(tunnel, uuid, fd)
				packet.writeclose(tunnel, uuid)
				uuid_to_fd[uuid] = nil
			end)
		elseif cmd == packet.CLOSE then
			local fd = uuid_to_fd[uuid]
			if fd then
				socket.close(fd)
				uuid_to_fd[uuid] = nil
			end
		elseif cmd == packet.DATA then
			local fd = uuid_to_fd[uuid]
			if fd then
				socket.write(fd, ud)
			end
		elseif cmd == packet.PING then
		end
	end
end

websocket.listen {
	addr = ":8080",
	handler = function(sock)
		print("from", sock.stream.remoteaddr)
		local ok, err = core.pcall(control, sock)
		if not ok then
			print(err)
			sock:close()
		end
	end,
}

http.listen {
	addr = ":8001",
	handler = function(req)
		if req.uri == "/metrics" then
			http.write(req.sock, 200, {
				["Content-Type"] = "text/plain"
			}, prometheus.gather())
		else
			print("Unsupport uri", req.uri)
			http.write(req.sock, 404,
				{["Content-Type"] = "text/plain"},
				"404 Page Not Found")
		end
	end,
}

dns.server("223.5.5.5:53")