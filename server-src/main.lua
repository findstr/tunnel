local core = require "sys.core"
local socket = require "sys.socket"
local dns = require "sys.dns"
local crypt = require "sys.crypt"
local packet = require "packet"

local key = core.envget("crypt")

local function tunnel_intenet(tunnelfd)
	local pk = packet.read(tunnelfd)
	local port = string.unpack("<I2", pk)
	local domain = pk:sub(2+1)
	domain = crypt.aesdecode(key, domain)
	print(domain, port)
	if dns.isname(domain) then
		domain = assert(dns.resolve(domain), domain)
	end
	local addr = string.format("%s:%d", domain, port)
	local fd = socket.connect(addr)
	--print("connect", fd, domain, addr)
	core.log("----tunnel bridge:", tunnelfd, fd)
	core.fork(packet.fromtunnel(tunnelfd, fd))
	core.fork(packet.fromweb(fd, tunnelfd))
end

socket.listen(core.envget("server"), function(tunnelfd, addr)
        print(tunnelfd, "from", addr)
	socket.limit(tunnelfd, 1024 * 1024 * 1024)
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
local function hello()
end
core.start(function()
for i = 1, 1025 do
	dns.resolve("www.google.com", "A")
end
print("---------------reserve----ok")
end)
