local core = require "sys.core"
local log = require "sys.logger"
local env = require "sys.env"
local socket = require "sys.net.tcp"
local dns = require "sys.dns"
local crypto = require "sys.crypto"
local packet = require "packet"
local http = require "http.server"
local prometheus = require "sys.metrics.prometheus"

local key = env.get("crypt")

local function tunnel_intenet(tunnelfd)
	local pk = packet.read(tunnelfd)
	local port = string.unpack("<I2", pk)
	local domain = pk:sub(2+1)
	domain = crypto.aesdecode(key, domain)
	print(domain, port)
	if dns.isname(domain) then
		domain = assert(dns.lookup(domain, dns.A), domain)
	end
	local addr = string.format("%s:%d", domain, port)
	local fd = socket.connect(addr)
	--print("connect", fd, domain, addr)
	log.info("----tunnel bridge:", tunnelfd, fd)
	core.fork(packet.fromtunnel(tunnelfd, fd))
	core.fork(packet.fromweb(fd, tunnelfd))
end

socket.listen(env.get("server"), function(tunnelfd, addr)
        print(tunnelfd, "from", addr)
	socket.limit(tunnelfd, 64 * 1024 * 1024)
	local ok, err = core.pcall(tunnel_intenet, tunnelfd)
	if not ok then
		print(err)
		socket.close(tunnelfd)
	end
end)

socket.listen(":4650", function(fd, addr)
	local google = socket.connect("108.177.98.108:465")
	assert(google, addr)
	core.fork(packet.transfer(fd, google))
	core.fork(packet.transfer(google, fd))
end)

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

core.start(function()
for i = 1, 1025 do
	dns.resolve("www.google.com", dns.A)
end
print("---------------reserve----ok")
print(key)
print(env.get("server"))
end)
