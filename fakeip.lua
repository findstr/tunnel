local core = require "core"
local path = "/etc/fakeip"
local M = {}

local f = io.open(path, "r")
if f then
	local hosts = f:read("*a")
	f:close()

	local content = hosts:match("# --- SWITCHHOSTS_CONTENT_START ---\n(.*)")
	if content then
	    hosts = content
	end

	for ip, host in hosts:gmatch("([%d%.]+)%s+([^%s]*)") do
		print(ip, host)
		M[ip] = host
	end
end

return M