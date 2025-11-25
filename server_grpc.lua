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
local prometheus = require "silly.metrics.prometheus"
local http = require "silly.net.http"
local channel = require "silly.sync.channel"
local wait_pool = {}

env.load("common.conf")

-- ============ Prometheus Metrics Definition ============
-- gRPC Stream metrics
local grpc_streams_total = prometheus.counter("tunnel_grpc_streams_total", "Total gRPC streams created", {"type"})
local grpc_streams_active = prometheus.gauge("tunnel_grpc_streams_active", "Active gRPC streams", {"type"})
local grpc_stream_errors = prometheus.counter("tunnel_grpc_stream_errors_total", "gRPC stream errors", {"type", "error_type"})

-- Connection metrics
local connections_total = prometheus.counter("tunnel_connections_total", "Total connections", {"proxy_type", "port"})
local connections_active = prometheus.gauge("tunnel_connections_active", "Active connections", {"proxy_type", "port"})
local connection_bytes = prometheus.counter("tunnel_connection_bytes_total", "Connection bytes transferred", {"proxy_type", "port", "direction"})
local connection_packets = prometheus.counter("tunnel_connection_packets_total", "Connection packets transferred", {"proxy_type", "port", "direction"})

-- Domain traffic metrics (server side tracking)
local domain_bytes = prometheus.counter("tunnel_domain_bytes_total", "Bytes per domain", {"domain", "direction"})
local domain_requests = prometheus.counter("tunnel_domain_requests_total", "Requests per domain", {"domain"})
local domain_errors = prometheus.counter("tunnel_domain_errors_total", "Errors per domain", {"domain", "error_type"})

-- Reverse proxy pool metrics
local reverse_pool_size = prometheus.gauge("tunnel_reverse_pool_size", "Total reverse proxy pool size", {"port"})
local reverse_pool_assigned = prometheus.counter("tunnel_reverse_pool_assigned_total", "Reverse proxy assignments", {"port"})
local reverse_pool_rejected = prometheus.counter("tunnel_reverse_pool_rejected_total", "Reverse proxy rejections due to empty pool", {"port"})

-- Error metrics
local errors_total = prometheus.counter("tunnel_errors_total", "Total errors by type", {"error_type"})

-- Latency metrics
local tunnel_latency = prometheus.gauge("tunnel_latency_ms", "Tunnel round-trip latency in milliseconds")

-- Domain tracking for limiting cardinality
local domain_tracker = {}
local MAX_TRACKED_DOMAINS = 100

-- Helper function to track domain (limit cardinality)
local function should_track_domain(domain)
	if domain_tracker[domain] then
		return true
	end
	local count = 0
	for _ in pairs(domain_tracker) do
		count = count + 1
	end
	if count < MAX_TRACKED_DOMAINS then
		domain_tracker[domain] = true
		return true
	end
	return false
end

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
	KeepAlive = function(req)
		-- Echo back the timestamp
		return {timestamp = req.timestamp}
	end,
	Connect = function(stream)
		-- Track stream
		grpc_streams_total:labels("connect"):inc()
		grpc_streams_active:labels("connect"):inc()

		-- Read first request, must have domain
		local req = stream:read()
		if not req then
			logger.error("[server] failed to read first request")
			grpc_streams_active:labels("connect"):dec()
			grpc_stream_errors:labels("connect", "read_failed"):inc()
			return
		end
		if not req.domain or req.domain == "" then
			logger.error("[server] first request must have domain")
			grpc_streams_active:labels("connect"):dec()
			grpc_stream_errors:labels("connect", "no_domain"):inc()
			return {code = 3, message = "domain required"}  -- INVALID_ARGUMENT
		end

		-- Decrypt and verify target
		local target, err = decrypt_target(req.domain)
		if not target then
			logger.errorf("[server] authentication failed: %s", err)
			grpc_streams_active:labels("connect"):dec()
			grpc_stream_errors:labels("connect", "auth_failed"):inc()
			errors_total:labels("auth_failed"):inc()
			return {code = 16, message = "unauthenticated"}  -- UNAUTHENTICATED
		end

		-- Extract domain from target (format: domain:port)
		local domain = target:match("^([^:]+)")
		if domain and should_track_domain(domain) then
			domain_requests:labels(domain):inc()
		end

		-- Connect to target
		local conn = tcp_connect(target)
		if not conn then
			logger.errorf("[server] failed to connect to %s", target)
			grpc_streams_active:labels("connect"):dec()
			grpc_stream_errors:labels("connect", "connect_failed"):inc()
			errors_total:labels("connect_failed"):inc()
			if domain and should_track_domain(domain) then
				domain_errors:labels(domain, "connect_failed"):inc()
			end
			return {code = 14, message = "connect failed"}  -- UNAVAILABLE
		end

		-- Extract port from target
		local port = target:match(":(%d+)$") or "unknown"
		connections_total:labels("forward", port):inc()
		connections_active:labels("forward", port):inc()

		logger.infof("[server] stream connected to %s", target)

		-- Create channel to synchronize two tasks
		local ch = channel.new()

		-- Fork task to read from conn and write to stream
		task.fork(function()
			while true do
				local data, err = conn:read(1)
				if err then
					logger.infof("[server] read conn err:%s", err)
					conn:close()
					-- Send close signal to client
					local pad_len = math.random(0, 512)
					local pad = string.rep(string.char(math.random(0, 255)), pad_len)
					stream:write({data = "", pad = pad})
					break
				end

				local more = conn:read(conn:unreadbytes())
				if more and more ~= "" then
					data = data .. more
				end

				-- Track bytes received from target
				local data_len = #data
				connection_bytes:labels("forward", port, "received"):add(data_len)
				connection_packets:labels("forward", port, "received"):inc()
				if domain and should_track_domain(domain) then
					domain_bytes:labels(domain, "received"):add(data_len)
				end

				-- Add random padding
				local pad_len = math.random(0, 512)
				local pad = string.rep(string.char(math.random(0, 255)), pad_len)
				local ok, err = stream:write({data = data, pad = pad})
				if not ok then
					logger.infof("[server] write stream failed: %s", err)
					conn:close()
					break
				end
			end
			ch:push(true)
		end)
		-- Write initial data if present
		if req.data and #req.data > 0 then
			connection_bytes:labels("forward", port, "sent"):add(#req.data)
			connection_packets:labels("forward", port, "sent"):inc()
			if domain and should_track_domain(domain) then
				domain_bytes:labels(domain, "sent"):add(#req.data)
			end
			conn:write(req.data)
		end
		-- Current task: read from stream and write to conn
		while true do
			req = stream:read()
			if not req then
				logger.info("[server] read stream closed")
				conn:close()
				break
			end
			local data = req.data
			if not data or #data == 0 then
				logger.info("[server] remote conn closed")
				conn:close()
				break
			end

			-- Track bytes sent to target
			connection_bytes:labels("forward", port, "sent"):add(#data)
			connection_packets:labels("forward", port, "sent"):inc()
			if domain and should_track_domain(domain) then
				domain_bytes:labels(domain, "sent"):add(#data)
			end

			local ok, err = conn:write(req.data)
			if not ok then
				logger.info("[server] write conn failed:", err)
				conn:close()
				break
			end
		end

		-- Wait for forked task to finish
		ch:pop()
		grpc_streams_active:labels("connect"):dec()
		connections_active:labels("forward", port):dec()
	end,
	Listen = function(stream)
		-- Track stream
		grpc_streams_total:labels("listen"):inc()
		grpc_streams_active:labels("listen"):inc()

		-- Read first request to get target port
		local req = stream:read()
		if not req then
			logger.error("[server] failed to read first listen request")
			grpc_streams_active:labels("listen"):dec()
			grpc_stream_errors:labels("listen", "read_failed"):inc()
			return
		end

		local target_port = req.port or 3100  -- Default to 3100 if not specified
		local port_str = tostring(target_port)
		logger.infof("[server] reverse agent registered for port %s", target_port)

		local co = task.running()
		table.insert(wait_pool, {
			co = co,
			stream = stream,
			port = target_port,  -- Store the target port
		})

		-- Update pool size metric
		reverse_pool_size:labels(port_str):set(#wait_pool)

		logger.info("[server] reverse agent connected, pool size:", #wait_pool)

		-- Wait for wakeup
		local conn = task.wait()

		-- Remove from pool size count
		reverse_pool_size:labels(port_str):set(#wait_pool)

		if not conn then
			logger.info("[server] reverse agent disconnected (wait failed)")
			grpc_streams_active:labels("listen"):dec()
			return
		end

		logger.info("[server] reverse tunnel established")
		connections_total:labels("reverse", port_str):inc()
		connections_active:labels("reverse", port_str):inc()

		-- Create channel to synchronize two tasks
		local ch = channel.new()

		-- Fork task to read from conn and write to stream
		task.fork(function()
			while true do
				local data, err = conn:read(1)
				if err then
					logger.infof("[server] read local conn err:%s", err)
					conn:close()
					-- Send close signal to client
					local pad_len = math.random(0, 512)
					local pad = string.rep(string.char(math.random(0, 255)), pad_len)
					stream:write({data = "", pad = pad})
					break
				end

				local more = conn:read(conn:unreadbytes())
				if more and more ~= "" then
					data = data .. more
				end

				-- Track bytes
				connection_bytes:labels("reverse", port_str, "received"):add(#data)
				connection_packets:labels("reverse", port_str, "received"):inc()

				local pad_len = math.random(0, 512)
				local pad = string.rep(string.char(math.random(0, 255)), pad_len)
				local ok, err = stream:write({data = data, pad = pad})
				if not ok then
					logger.infof("[server] write stream failed: %s", err)
					conn:close()
					break
				end
			end
			ch:push(true)
		end)

		-- Current task: read from stream and write to conn
		while true do
			req = stream:read()
			if not req then
				logger.info("[server] read stream closed")
				conn:close()
				break
			end
			local data = req.data
			if not data or #data == 0 then
				logger.info("[server] remote conn closed")
				conn:close()
				break
			end

			-- Track bytes
			connection_bytes:labels("reverse", port_str, "sent"):add(#data)
			connection_packets:labels("reverse", port_str, "sent"):inc()

			local ok, err = conn:write(req.data)
			if not ok then
				logger.info("[server] write conn failed:", err)
				conn:close()
				break
			end
		end

		-- Wait for forked task to finish
		ch:pop()
		grpc_streams_active:labels("listen"):dec()
		connections_active:labels("reverse", port_str):dec()
	end
})

-- Start Reverse Proxy Listener (port 3100 for Loki)
local l_rev_3100, err_rev_3100 = tcp.listen {
	addr = "0.0.0.0:3100",
	accept = function(conn)
		logger.infof("[server] reverse proxy (3100) accept:%s", conn:remoteaddr())

		-- Find an agent registered for port 3100
		local found_idx = nil
		for i, item in ipairs(wait_pool) do
			if item.port == 3100 then
				found_idx = i
				break
			end
		end

		if not found_idx then
			logger.error("[server] no available reverse agent for port 3100")
			reverse_pool_rejected:labels("3100"):inc()
			errors_total:labels("no_reverse_agent"):inc()
			conn:close()
			return
		end

		local item = table.remove(wait_pool, found_idx)
		reverse_pool_assigned:labels("3100"):inc()
		reverse_pool_size:labels("3100"):set(#wait_pool)
		logger.infof("[server] using reverse agent for port 3100, remaining pool size: %s", #wait_pool)

		-- Wakeup the Listen RPC handler with the connection
		task.wakeup(item.co, conn)
	end
}
assert(l_rev_3100, err_rev_3100)
logger.infof("[server] reverse proxy listening on 0.0.0.0:3100 (Loki)")

-- Start Reverse Proxy Listener (port 9090 for Prometheus)
local l_rev_9090, err_rev_9090 = tcp.listen {
	addr = "0.0.0.0:9090",
	accept = function(conn)
		logger.infof("[server] reverse proxy (9090) accept:%s", conn:remoteaddr())

		-- Find an agent registered for port 9090
		local found_idx = nil
		for i, item in ipairs(wait_pool) do
			if item.port == 9090 then
				found_idx = i
				break
			end
		end

		if not found_idx then
			logger.error("[server] no available reverse agent for port 9090")
			reverse_pool_rejected:labels("9090"):inc()
			errors_total:labels("no_reverse_agent"):inc()
			conn:close()
			return
		end

		local item = table.remove(wait_pool, found_idx)
		reverse_pool_assigned:labels("9090"):inc()
		reverse_pool_size:labels("9090"):set(#wait_pool)
		logger.infof("[server] using reverse agent for port 9090, remaining pool size: %s", #wait_pool)

		-- Wakeup the Listen RPC handler with the connection
		task.wakeup(item.co, conn)
	end
}
assert(l_rev_9090, err_rev_9090)
logger.infof("[server] reverse proxy listening on 0.0.0.0:9090 (Prometheus)")

-- Start gRPC server
local server = grpc.listen {
	addr = "0.0.0.0:443",
	registrar = registrar,
}

assert(server, "failed to start grpc server")
logger.infof("[server] grpc tunnel server started on 0.0.0.0:443")

-- Start Prometheus metrics server
local metrics_server = http.listen {
	addr = "0.0.0.0:9001",
	handler = function(stream)
		if stream.path == "/metrics" then
			local metrics_data = prometheus.gather()
			stream:respond(200, {
				["content-type"] = "text/plain; version=0.0.4; charset=utf-8",
				["content-length"] = #metrics_data,
			})
			stream:closewrite(metrics_data)
		else
			stream:respond(404, {["content-type"] = "text/plain"})
			stream:closewrite("Not Found")
		end
	end
}
assert(metrics_server, "failed to start metrics server")
logger.infof("[server] prometheus metrics server started on 0.0.0.0:9001")
