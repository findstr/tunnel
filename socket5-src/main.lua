local core = require "sys.core"
local socket = require "sys.socket"
local crypt = require "sys.crypt"
local packet = require "packet"
local key = assert(core.envget("crypt"), "crypt key")
local serveraddr  = assert(core.envget("server"), "server")
local function auth(fd)
	print("auth start")
	local str = socket.read(fd, 3)
	local ver, nr, method = string.unpack("<I1I1I1", str)
	print(ver, nr, method)
	assert(ver == 0x05)
	local noauth = false
	if method == 0x0 then
		noauth = true
	elseif nr > 1 then
		nr = nr - 1
		str = socket.read(fd, nr)
		for i = 1, str do
			if str:byte(i) == 0x0 then
				noauth = true
			end
		end
	end
	assert(noauth, "not support auth")
	local ack = string.pack("<I1I1", 0x05, 0x00)
	socket.write(fd, ack)
	print("auth ok")
end

local function bridge_tunnel(fd, domain, port, firstpacket)
	local tunnelfd = socket.connect(serveraddr)
	print("connect server fd", serveraddr, tunnelfd)
	local hdr = string.pack("<I2", port)
	domain = crypt.aesencode(key, domain)
	packet.write(tunnelfd, hdr .. domain)
	core.fork(packet.fromweb(fd, tunnelfd, firstpacket))
	core.fork(packet.fromtunnel(tunnelfd, fd))

end

local function connect(fd)
	local str = socket.read(fd, 4)
	local ver, req, rev, addr = string.unpack("<I1I1I1I1", str)
	print("connect", ver, req, rev, addr)
	assert(addr == 3, "only support domain")
	--domain len
	str = socket.read(fd, 1)
	local len = str:byte(1)
	--domain name
	local domain = socket.read(fd, len)
	print("connect domain", domain)
	str = socket.read(fd, 2)
	local port = string.unpack(">I2", str)
	print("connect port", port)
	bridge_tunnel(fd, domain, port)
	local ack = "\x05\x00\x00\x01\x00\x00\x00\x00\xe9\xc7"
	socket.write(fd, ack)
end

local function socket5(fd)
	auth(fd)
	connect(fd)
end


socket.listen(core.envget("socket5"), function(fd, addr)
	print(fd, "from", addr)
	local ok, err = core.pcall(socket5, fd)
	if not ok then
		print(err)
		socket.close(fd)
	end
end)

local function sni(fd)
	--record
	local head = socket.read(fd, 5)
	local typ, major, minor, len = string.unpack(">I1I1I1I2", head)
	assert(typ == 22, typ)
	local offset = 1
	local body = socket.read(fd, len)
	local msgtype, n = string.unpack(">I1I3", body, offset)
	assert(msgtype == 1)
	offset = offset + 4 + 2 + 4 + 28 --msgtype, msglen client ver random
	local session_len = string.unpack(">I1", body, offset)
	offset = offset + session_len + 1
	local chiper_len = string.unpack(">I2", body, offset)
	offset = offset + chiper_len + 2
	local compress_len = string.unpack(">I1", body, offset)
	offset = offset + compress_len + 1
	assert(offset < len)
	--extention
	local ext_len = string.unpack(">I2", body, offset)
	offset = offset + 2
	while ext_len > 0 do
		local t, l = string.unpack(">I2I2", body, offset)
		offset = offset + 4
		ext_len = ext_len - 4
		if t == 0x0 then --server name
			while l > 0 do
				local list_len = string.unpack(">I2", body, offset)
				offset = offset + 2
				l = l - 2
				while list_len > 0 do
					local nt, nl = string.unpack(">I2I1", body, offset)
					offset = offset + 3
					if nt == 0 then
						return string.sub(body, offset, offset + nl - 1), head .. body
					end
					offset = offset + nl
				end
			end
			return nil
		end
		offset = offset + l
		ext_len = ext_len - l
	end
	return nil
end

socket.listen(":443", function(fd, addr)
	local domain, dat = assert(sni(fd))
	print("https:", #domain, fd, addr, domain, #dat)
	bridge_tunnel(fd, domain, 443, dat)
end)


