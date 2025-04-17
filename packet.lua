local env = require "core.env"
local logger = require "core.logger"
local socket = require "core.net.tcp"
local cipher = require "core.crypto.cipher"

local key = assert(env.get("crypt"), "crypt")
local iv = "\xa3\x4f\x91\x22\xb7\xcd\x89\x05\x6a\x19\xef\x0c\x7d\x31\x82\xbb"

local AUTH<const> = 1
local HELLO<const> = 2
local OPEN<const> = 3
local CLOSE<const> = 4
local DATA<const> = 5
local PING<const> = 6

local format = string.format
local pack = string.pack
local unpack = string.unpack


local encryptor = cipher.encryptor("aes-128-cbc", key, iv)
local decryptor = cipher.decryptor("aes-128-cbc", key, iv)

local M = {
	AUTH = AUTH,
	HELLO = HELLO,
	OPEN = OPEN,
	CLOSE = CLOSE,
	DATA = DATA,
}

function M.write(fd, dat)
	encryptor:reset(key, iv)
	local enc = encryptor:final(dat)
	local len = #enc
	local hdr = string.pack("<I4", len)
	socket.write(fd, hdr .. enc)
end

function M.read(fd)
	local len, err = socket.read(fd, 4)
	if not len then
		return nil, err
	end
	len = string.unpack("<I4", len)
	local dat, err = socket.read(fd, len)
	if not dat then
		return nil, err
	end
	decryptor:reset(key, iv)
	local dec = decryptor:final(dat)
	return dec, nil
end


function M.writeauth(fd, uuid, key)
	local pk = pack("<I1I8", AUTH, uuid) .. key
	return M.write(fd, pk)
end

function M.writehello(fd, uuid)
	local pk = pack("<I1I8", HELLO, uuid)
	return M.write(fd, pk)
end

function M.writeopen(fd, uuid, domain, port)
	local pk = pack("<I1I8", OPEN, uuid) .. format("%s:%d", domain, port)
	return M.write(fd, pk)
end

function M.writeclose(fd, uuid)
	local pk = pack("<I1I8", CLOSE, uuid)
	return M.write(fd, pk)
end

function M.writedata(fd, uuid, data)
	logger.info("write DATA uuid:", uuid, #data)
	local pk = pack("<I1I8", DATA, uuid) .. data
	return M.write(fd, pk)
end

function M.writeping(fd)
	local pk = pack("<I1I8", PING, 0)
	return M.write(fd, pk)
end

function M.readpacket(fd)

	local pk, err = M.read(fd)
	if not pk then
		logger.info("readpacket", fd, "read err:", err)
		return nil, nil, err
	end
	local cmd, uuid = unpack("<I1I8", pk)
	if cmd == DATA then
		local dat = pk:sub(10)
		logger.infof("DATA uuid:%s data:%s", uuid, #dat)
		return cmd, uuid, dat
	elseif cmd == OPEN then
		local addr = pk:sub(10)
		logger.infof("OPEN uuid:%s addr:%s", uuid, addr)
		return cmd, uuid, addr
	elseif cmd == CLOSE then
		logger.infof("CLOSE uuid:%s", uuid)
		return cmd, uuid, ""
	elseif cmd == HELLO then
		logger.infof("HELLO uuid:%s", uuid)
		return cmd, uuid
	elseif cmd == AUTH then
		local key = pk:sub(10)
		logger.infof("AUTH uuid:%s key:%s", uuid, key)
		return cmd, uuid, key
	elseif cmd == PING then
		logger.infof("PING uuid:%s", uuid)
		return cmd, uuid
	else
		logger.errorf("unkonw packet:%s", cmd)
		return nil, nil, "unkonw packet"
	end
end

function M.fromraw(tunnelfd, uuid, fd)
	while true do
		local d = socket.read(fd, 1)
		if not d then
			break
		end
		local d1 = socket.readall(fd, 1024*1024)
		if d1 and d1 ~= "" then
			d = d .. d1
		end
		if #d > 0 then
			M.writedata(tunnelfd, uuid, d)
		end
	end
end

return M

