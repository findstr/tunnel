local core = require "core"
local logger = require "core.logger"
local socket = require "core.net.tcp"
local env = require "core.env"

env.load("./common.conf")

local packet = require "packet"

local serveraddr  = assert(env.get("server"), "server")
local key = assert(env.get("crypt"), "crypt")

local idx = 0
local round_robin = 1
local tunnel_fds = {}
local tunnelfd_to_uuid = {}
local uuid_to_fd = {}
local tunnel_count<const> = 128

local function check_tunnels()
	if #tunnel_fds >= tunnel_count then
		return
	end
	for i = #tunnel_fds + 1, tunnel_count do
		local fd = socket.connect(serveraddr)
		logger.infof("connect to server:%s fd:%s", serveraddr, fd)
		if not fd then
			logger.error("connect server failed")
		else
			packet.writeauth(fd, 0, env.get("crypt"))
			local cmd, uuid_start, err = packet.readpacket(fd)
			if not cmd then
				logger.errorf("read server failed: %s", err)
				core.sleep(100)
			else
				tunnel_fds[#tunnel_fds + 1] = fd
				tunnelfd_to_uuid[fd] = uuid_start
				core.fork(function()
					while true do
						local cmd, uuid, data = packet.readpacket(fd)
						if not cmd or not uuid then -- tunnel closed
							for uuid, sfd in pairs(uuid_to_fd) do
								local uuid_tag = uuid & 0xffffffff00000000
								if uuid_tag == uuid_start then
									socket.close(sfd)
									uuid_to_fd[uuid] = nil
								end
							end
							for i, tfd in pairs(tunnel_fds) do
								if tfd == fd then
									table.remove(tunnel_fds, i)
									tunnelfd_to_uuid[tfd] = nil
									break
								end
							end
							break
						end
						if cmd == packet.DATA then
							local fd = uuid_to_fd[uuid]
							if fd then
								socket.write(fd, data)
							end
						elseif cmd == packet.CLOSE then
							local fd = uuid_to_fd[uuid]
							if fd then
								socket.close(fd)
								uuid_to_fd[uuid] = nil
							end
						end
					end
				end)
			end
		end
	end
end

local function auth(fd)
	logger.info("auth start")
	local str = socket.read(fd, 3)
	if not str then
		return
	end
	local ver, nr, method = string.unpack("<I1I1I1", str)
	print(ver, nr, method)
	assert(ver == 0x05)
	local noauth = false
	if method == 0x0 then
		noauth = true
	elseif nr > 1 then
		nr = nr - 1
		str = socket.read(fd, nr)
		if not str then
			logger.error("auth read failed")
			return
		end
		for i = 1, #str do
			if str:byte(i) == 0x0 then
				noauth = true
			end
		end
	end
	assert(noauth, "not support auth")
	local ack = string.pack("<I1I1", 0x05, 0x00)
	socket.write(fd, ack)
	logger.info("auth success")
end

local function transfering(fd, domain, port, firstpacket)
	repeat
		check_tunnels()
	until #tunnel_fds > 0
	local id = (idx + 1) & 0x7fffffff
	idx = id
	local rr = (round_robin + 1) % #tunnel_fds + 1
	round_robin = rr
	local tunnelfd =tunnel_fds[rr]
	local uuid = tunnelfd_to_uuid[tunnelfd] + id
	uuid_to_fd[uuid] = fd
	logger.info("write open:", uuid)
	packet.writeopen(tunnelfd, uuid, domain, port)
	if firstpacket then
		packet.writedata(tunnelfd, uuid, firstpacket)
	end
	core.fork(function()
		packet.fromraw(tunnelfd, uuid, fd)
	end)
end

local function connect(fd)
	local str = socket.read(fd, 4)
	local ver, req, rev, addr = string.unpack("<I1I1I1I1", str)
	logger.info("connect", ver, req, rev, addr)
	assert(addr == 3, "only support domain")
	--domain len
	str = socket.read(fd, 1)
	local len = str:byte(1)
	--domain name
	local domain = socket.read(fd, len)
	logger.info("connect domain", domain)
	str = socket.read(fd, 2)
	local port = string.unpack(">I2", str)
	logger.info("connect port", port)
	transfering(fd, domain, port)
	local ack = "\x05\x00\x00\x01\x00\x00\x00\x00\xe9\xc7"
	socket.write(fd, ack)
end

local function socket5(fd)
	auth(fd)
	connect(fd)
end


socket.listen(env.get("socket5"), function(fd, addr)
	logger.info(fd, "from", addr)
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

socket.listen("0.0.0.0:443", function(fd, addr)
	local domain, dat = assert(sni(fd))
	if not domain then
		logger.errorf("connect domain err:", domain, dat)
		return
	end
	logger.infof("https://%s addr:%s fd:%s datalen:%s", domain, addr, fd, #dat)
	transfering(fd, domain, 443, dat)
end)

socket.listen("0.0.0.0:9930", function(fd, addr)
	transfering(fd, "imap.gmail.com", 993, dat)
end)


core.fork(function()
	while true do
		core.sleep(30000)
		for tunnelfd in pairs(tunnelfd_to_uuid) do
			packet.writeping(tunnelfd)
		end
	end
end)

check_tunnels()

