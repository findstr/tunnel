local silly = require "silly"
local dns = require "silly.net.dns"
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
local prometheus = require "silly.metrics.prometheus"
local http = require "silly.net.http"
local channel = require "silly.sync.channel"

env.load("./common.conf")

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

-- Domain traffic metrics (使用动态label，但限制top N)
local domain_bytes = prometheus.counter("tunnel_domain_bytes_total", "Bytes per domain", {"domain", "direction"})
local domain_requests = prometheus.counter("tunnel_domain_requests_total", "Requests per domain", {"domain"})
local domain_errors = prometheus.counter("tunnel_domain_errors_total", "Errors per domain", {"domain", "error_type"})

-- Reverse proxy metrics
local reverse_pool_waiting = prometheus.gauge("tunnel_reverse_pool_waiting", "Reverse agents waiting in pool", {"port"})
local reverse_agent_reconnect = prometheus.counter("tunnel_reverse_agent_reconnect_total", "Reverse agent reconnections", {"port"})

-- Error metrics
local errors_total = prometheus.counter("tunnel_errors_total", "Total errors by type", {"error_type"})

-- Latency metrics
local tunnel_latency = prometheus.gauge("tunnel_latency_ms", "Tunnel round-trip latency in milliseconds")

-- Domain tracking for limiting cardinality
local domain_tracker = {}
local MAX_TRACKED_DOMAINS = 100  -- 只跟踪top 100域名

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

-- Create tunnel for a connection
local function create_tunnel(conn, domain, port, firstdata, proxy_type)
	local target = string.format("%s:%d", domain, port)
	local port_str = tostring(port)

	-- Track domain metrics (with cardinality limit)
	if should_track_domain(domain) then
		domain_requests:labels(domain):inc()
	end

	-- Track stream creation
	grpc_streams_total:labels("connect"):inc()
	grpc_streams_active:labels("connect"):inc()

	-- Open bidirectional stream
	local stream<close>, err = service:Connect()
	if not stream then
		logger.errorf("[client] failed to create stream: %s", err)
		grpc_streams_active:labels("connect"):dec()
		grpc_stream_errors:labels("connect", "create_failed"):inc()
		errors_total:labels("stream_create_failed"):inc()
		if should_track_domain(domain) then
			domain_errors:labels(domain, "stream_create_failed"):inc()
		end
		conn:close()
		return
	end

	-- Track connection (after stream is successfully created)
	connections_total:labels(proxy_type, port_str):inc()
	connections_active:labels(proxy_type, port_str):inc()
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

	-- Create channel to synchronize two tasks
	local ch = channel.new()

	-- Fork task to read from local conn and write to stream
	task.fork(function()
		while true do
			local data, err = conn:read(1)
			if err then
				logger.info("[client] read conn failed:", err)
				conn:close()
				-- Send close signal to server
				local pad_len = math.random(0, 512)
				local pad = string.rep(string.char(math.random(0, 255)), pad_len)
				stream:write({data = "", pad = pad})
				break
			end
			local more = conn:read(conn:unreadbytes())
			if more and more ~= "" then
				data = data .. more
			end

			-- Track bytes sent
			local data_len = #data
			connection_bytes:labels(proxy_type, port_str, "sent"):add(data_len)
			connection_packets:labels(proxy_type, port_str, "sent"):inc()
			if should_track_domain(domain) then
				domain_bytes:labels(domain, "sent"):add(data_len)
			end

			local pad_len = math.random(0, 512)
			local pad = string.rep(string.char(math.random(0, 255)), pad_len)

			local ok, err = stream:write({data = data, pad = pad})
			if not ok then
				logger.infof("[client] write stream failed: %s", err)
				conn:close()
				break
			end
		end
		ch:push(true)
	end)
	-- Current task: read from stream and write to conn
	while true do
		local resp = stream:read()
		if not resp then
			logger.info("[client] read stream closed:", stream.message)
			conn:close()
			break
		end
		local data = resp.data
		if not data or #data == 0 then
			conn:close()
			break
		end

		-- Track bytes received
		local data_len = #data
		connection_bytes:labels(proxy_type, port_str, "received"):add(data_len)
		connection_packets:labels(proxy_type, port_str, "received"):inc()
		if should_track_domain(domain) then
			domain_bytes:labels(domain, "received"):add(data_len)
		end

		local ok, err = conn:write(resp.data)
		if not ok then
			logger.info("[client] write conn failed:", err)
			conn:close()
			break
		end
	end

	-- Wait for forked task to finish
	ch:pop()
	grpc_streams_active:labels("connect"):dec()
	connections_active:labels(proxy_type, port_str):dec()
end

-- SOCKS5 authentication
local function socks5_auth(conn)
	local str, err = conn:read(3)
	if err then
		return false
	end

	local ver, nr, method = string.unpack("<I1I1I1", str)
	if ver ~= 0x05 then
		logger.errorf("[client] invalid socks version: %s", ver)
		return false
	end

	local noauth = (method == 0x0)
	if not noauth and nr > 1 then
		nr = nr - 1
		str, err = conn:read(nr)
		if err then
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
	local str, err = conn:read(4)
	if err then
		return nil, nil
	end

	local ver, cmd, rsv, atyp = string.unpack("<I1I1I1I1", str)
	if cmd ~= 1 then  -- CONNECT
		logger.errorf("[client] unsupported socks command: %s", cmd)
		return nil, nil
	end

	local domain
	if atyp == 3 then  -- Domain name
		str, err = conn:read(1)
		if err then
			return nil, nil
		end
		local len = str:byte(1)
		domain, err = conn:read(len)
		if err then
			return nil, nil
		end
	elseif atyp == 1 then  -- IPv4
		local ip_bytes, err = conn:read(4)
		if err then
			return nil, nil
		end
		domain = string.format("%d.%d.%d.%d", ip_bytes:byte(1, 4))
	else
		logger.errorf("[client] unsupported address type: %s", atyp)
		return nil, nil
	end

	str, err = conn:read(2)
	if err then
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
		errors_total:labels("socks5_auth_failed"):inc()
		return
	end

	local domain, port = socks5_connect(conn)
	if not domain then
		conn:close()
		errors_total:labels("socks5_connect_failed"):inc()
		return
	end

	logger.infof("[client] socks5 target: %s:%s", domain, port)
	create_tunnel(conn, domain, port, nil, "socks5")
end

-- TLS SNI parser
local function parse_sni(conn)
	local head, err = conn:read(5)
	if err then
		return nil, nil
	end

	local typ, major, minor, len = string.unpack(">I1I1I1I2", head)
	logger.debugf("[client] TLS record: type=%s, version=%s.%s, len=%s", typ, major, minor, len)

	if typ ~= 22 then  -- Handshake
		logger.debugf("[client] not a tls handshake: type=%s (expected 22)", typ)
		return nil, nil
	end

	local body, err = conn:read(len)
	if err then
		return nil, nil
	end
	logger.debugf("[client] read TLS body: %s bytes", #body)

	local offset = 1
	if offset > #body then
		return nil, nil
	end

	local msgtype = string.unpack(">I1", body, offset)
	logger.debugf("[client] handshake msgtype=%s", msgtype)

	if msgtype ~= 1 then  -- ClientHello
		logger.debugf("[client] not ClientHello: msgtype=%s", msgtype)
		return nil, nil
	end

	-- msgtype(1) + msglen(3) + client_ver(2) + random(32) = 38 bytes
	offset = offset + 1 + 3 + 2 + 32
	if offset > #body then
		logger.debugf("[client] body too short: offset=%s, len=%s", offset, #body)
		return nil, nil
	end

	local session_len = string.unpack(">I1", body, offset)
	logger.debugf("[client] session_id length=%s", session_len)
	offset = offset + 1 + session_len

	if offset + 2 > #body then
		logger.debugf("[client] body too short for cipher suites: offset=%s", offset)
		return nil, nil
	end

	local cipher_len = string.unpack(">I2", body, offset)
	logger.debugf("[client] cipher suites length=%s", cipher_len)
	offset = offset + 2 + cipher_len

	if offset + 1 > #body then
		logger.debugf("[client] body too short for compression: offset=%s", offset)
		return nil, nil
	end

	local compress_len = string.unpack(">I1", body, offset)
	logger.debugf("[client] compression methods length=%s", compress_len)
	offset = offset + 1 + compress_len

	if offset + 2 > #body then
		logger.debugf("[client] no extensions present")
		return nil, nil
	end

	-- Extensions
	local ext_len = string.unpack(">I2", body, offset)
	logger.debugf("[client] extensions total length=%s", ext_len)
	offset = offset + 2

	while ext_len > 0 do
		if offset + 4 > #body then
			break
		end

		local t, l = string.unpack(">I2I2", body, offset)
		logger.debugf("[client] extension: type=%s, len=%s", t, l)
		offset = offset + 4
		ext_len = ext_len - 4

		if t == 0x0 then  -- server_name extension
			logger.debug("[client] found server_name extension")
			while l > 0 do
				if offset + 2 > #body then
					return nil, nil
				end

				local list_len = string.unpack(">I2", body, offset)
				offset = offset + 2
				l = l - 2

				while list_len > 0 do
					if offset + 3 > #body then
						return nil, nil
					end

					local nt, nl = string.unpack(">I1I2", body, offset)
					offset = offset + 3
					list_len = list_len - 3

					if nt == 0 then  -- host_name
						if offset + nl > #body then
							return nil, nil
						end
						local domain = string.sub(body, offset, offset + nl - 1)
						logger.debugf("[client] extracted SNI domain: %s", domain)
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
	local domain, firstdata = parse_sni(conn)
	if not domain then
		logger.error("[client] failed to parse sni")
		conn:close()
		errors_total:labels("sni_parse_failed"):inc()
		return
	end
	create_tunnel(conn, domain, 443, firstdata, "sni")
end

-- Start SOCKS5 proxy
local l, err = tcp.listen {
	addr = "0.0.0.0:1080",
	accept = function(conn)
		logger.infof("[client] socks5 accept:%s", conn:remoteaddr())
		socks5_handler(conn)
	end
}
assert(l, err)

-- Start SNI proxy
local l2, err2 = tcp.listen {
	addr = "0.0.0.0:443",
	accept = function(conn)
		logger.infof("[client] sni accept:%s", conn:remoteaddr())
		sni_handler(conn)
	end
}
assert(l2, err2)

local l3, err3 = tcp.listen {
	addr = "0.0.0.0:993",
	accept = function(conn)
		logger.info("[client] imap accept:", conn:remoteaddr())
		create_tunnel(conn, "imap.gmail.com", 993, nil, "fixed")
	end
}
assert(l3, err3)

logger.info("[client] sni proxy listening on 0.0.0.0:443")
logger.info("[client] socks5 proxy listening on 0.0.0.0:1080")
logger.info("[client] fixed proxy listening on 0.0.0.0:993 -> imap.gmail.com:993")

-- Reverse Agent Logic (port-aware)
local function reverse_agent(listen_port, target_addr)
	local port_str = tostring(listen_port)

	local stream<close>, err = service:Listen()
	if not stream then
		logger.errorf("[client] reverse agent (port %s) failed to listen: %s", listen_port, err)
		errors_total:labels("reverse_listen_failed"):inc()
		reverse_agent_reconnect:labels(port_str):inc()
		time.sleep(1000)
		-- Retry by forking a new agent
		task.fork(function()
			reverse_agent(listen_port, target_addr)
		end)
		return
	end

	-- Track stream
	grpc_streams_total:labels("listen"):inc()
	grpc_streams_active:labels("listen"):inc()
	reverse_pool_waiting:labels(port_str):inc()

	logger.infof("[client] reverse agent registered for port %s, waiting for traffic...", listen_port)

	-- Send first request with port information
	local pad_len = math.random(0, 512)
	local pad = string.rep(string.char(math.random(0, 255)), pad_len)
	local ok, err = stream:write({
		port = listen_port,
		data = "",
		pad = pad,
	})
	if not ok then
		logger.errorf("[client] failed to send initial listen request: %s", err)
		grpc_streams_active:labels("listen"):dec()
		reverse_pool_waiting:labels(port_str):dec()
		reverse_agent_reconnect:labels(port_str):inc()
		time.sleep(1000)
		-- Retry by forking a new agent
		task.fork(function()
			reverse_agent(listen_port, target_addr)
		end)
		return
	end

	-- Wait for first packet from server (signaling a new connection)
	local req, err = stream:read()
	if not req then
		logger.info("[client] reverse agent stream closed before traffic")
		grpc_streams_active:labels("listen"):dec()
		reverse_pool_waiting:labels(port_str):dec()
		reverse_agent_reconnect:labels(port_str):inc()
		time.sleep(1000)
		-- Retry by forking a new agent
		task.fork(function()
			reverse_agent(listen_port, target_addr)
		end)
		return
	end

	-- Got traffic, no longer waiting
	reverse_pool_waiting:labels(port_str):dec()
	connections_total:labels("reverse", port_str):inc()
	connections_active:labels("reverse", port_str):inc()

	-- Immediately fork a new agent to keep pool available
	task.fork(function()
		reverse_agent(listen_port, target_addr)
	end)
	logger.debugf("[client] forked new reverse agent for port %s to maintain pool", listen_port)

	-- Parse target address and resolve DNS if needed
	local host, port = target_addr:match("^([^:]+):(%d+)$")
	if not host or not port then
		logger.errorf("[client] invalid target address format: %s", target_addr)
		grpc_streams_active:labels("listen"):dec()
		connections_active:labels("reverse", port_str):dec()
		return
	end

	-- Resolve DNS for container name
	local ip, err = dns.lookup(host, dns.A)
	if not ip then
		logger.errorf("[client] failed to resolve %s: %s", host, err)
		errors_total:labels("dns_failed"):inc()
		grpc_streams_active:labels("listen"):dec()
		connections_active:labels("reverse", port_str):dec()
		return
	end

	local resolved_addr = ip .. ":" .. port

	-- Connect to local service
	local conn, err = tcp.connect(resolved_addr)
	if not conn then
		logger.errorf("[client] failed to connect to %s (resolved from %s): %s", resolved_addr, target_addr, err)
		errors_total:labels("connect_failed"):inc()
		grpc_streams_active:labels("listen"):dec()
		connections_active:labels("reverse", port_str):dec()
		return
	end

	logger.infof("[client] reverse traffic received (port %s), connecting to: %s (%s)", listen_port, target_addr, resolved_addr)

	-- Create channel to synchronize two tasks
	local ch = channel.new()

	-- Fork task to read from conn and write to stream
	task.fork(function()
		while true do
			local data, err = conn:read(1)
			if err then
				logger.errorf("[client] reverse agent read error: %s", err)
				conn:close()
				-- Send close signal to server
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
			connection_bytes:labels("reverse", port_str, "sent"):add(#data)
			connection_packets:labels("reverse", port_str, "sent"):inc()

			local pad_len = math.random(0, 512)
			local pad = string.rep(string.char(math.random(0, 255)), pad_len)
			local ok, err = stream:write({data = data, pad = pad})
			if not ok then
				logger.errorf("[client] reverse agent write stream failed: %s", err)
				conn:close()
				break
			end
		end
		ch:push(true)
	end)

	-- Write the first packet we already read
	if req.data and #req.data > 0 then
		connection_bytes:labels("reverse", port_str, "received"):add(#req.data)
		connection_packets:labels("reverse", port_str, "received"):inc()
		conn:write(req.data)
	end

	-- Continue reading from stream and writing to conn
	while true do
		req = stream:read()
		if not req then
			break
		end
		local data = req.data
		if not data or #data == 0 then
			break
		end

		-- Track bytes
		connection_bytes:labels("reverse", port_str, "received"):add(#data)
		connection_packets:labels("reverse", port_str, "received"):inc()

		local ok, err = conn:write(data)
		if not ok then
			break
		end
	end

	-- Wait for forked task to finish
	ch:pop()
	conn:close()
	grpc_streams_active:labels("listen"):dec()
	connections_active:labels("reverse", port_str):dec()
	logger.infof("[client] reverse agent (port %s) connection finished", listen_port)
end

-- Check if reverse proxy is enabled
local enable_reverse = env.get("enable_reverse_proxy")
if enable_reverse == "true" then
	-- Start reverse agents for Loki (3100)
	task.fork(function()
		reverse_agent(3100, "loki:3100")
	end)
	logger.info("[client] started 4 reverse agents for port 3100 -> loki:3100")
	-- Start reverse agents for Prometheus (9090)
	task.fork(function()
		reverse_agent(9090, "prometheus:9090")
	end)
	logger.info("[client] started reverse agent for port 9090 -> prometheus:9090")
else
	logger.info("[client] reverse proxy disabled (ENABLE_REVERSE_PROXY not set to 'true')")
end

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
logger.infof("[client] prometheus metrics server started on 0.0.0.0:9003")

-- Start KeepAlive heartbeat task
task.fork(function()
	logger.info("[client] starting keepalive heartbeat task")
	while true do
		local start_time = time.monotonic()
		local timestamp_ms = start_time
		-- Call KeepAlive RPC
		local ok, resp_or_err = pcall(function()
			return service:KeepAlive({timestamp = timestamp_ms})
		end)

		if ok and resp_or_err then
			local end_time = time.monotonic()
			local latency_ms = (end_time - start_time)
			tunnel_latency:set(latency_ms)
			logger.infof("[client] keepalive latency: %s ms", latency_ms)
		else
			logger.errorf("[client] keepalive failed: %s", resp_or_err or "unknown error")
			errors_total:labels("keepalive_failed"):inc()
		end

		time.sleep(1000)  -- Sleep 1 second
	end
end)