# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT
Dir.chdir(__dir__)

require 'socket'
require 'date'
require 'zlib'
require 'logger'
require 'optparse'

LOG_FILE_PATH = ".\\logs\\#{DateTime.now.to_s.gsub(?:, ?-)}.log".freeze
LOGS_DIRECTORY = File.dirname(LOG_FILE_PATH).freeze
Dir.mkdir(LOGS_DIRECTORY) unless File.directory?(LOGS_DIRECTORY)
FILE_LOGGER = Logger.new(LOG_FILE_PATH, level: Logger::DEBUG, binmode: true).freeze
TERMINAL_LOGGER = Logger.new(STDOUT, level: Logger::INFO, binmode: true)
LOGGER_SEVERITY_COLORS = {
  "DEBUG" =>   "\e[37m",   # White
  "INFO"  =>   "\e[32m",   # Green
  "WARN"  =>   "\e[33m",   # Yellow
  "ERROR" =>   "\e[31m",   # Red
  "FATAL" =>   "\e[35m",   # Magenta
  "UNKNOWN" => "\e[36m"    # Cyan
}.freeze
COLOR_RESET = "\e[0m"
ORIGINAL_LOGGER_FORMATTER = Logger::Formatter.new

TERMINAL_LOGGER.formatter = proc do |severity, datetime, progname, msg|
  color = LOGGER_SEVERITY_COLORS[severity] || ""
  line = ORIGINAL_LOGGER_FORMATTER.call(severity, datetime, progname, msg)
  line.sub(severity, "#{color}#{severity}#{COLOR_RESET}")
end

TERMINAL_LOGGER.freeze

def parse_hosts_file()
  windows_hosts_file_path = "C:\\Windows\\System32\\drivers\\etc\\hosts"
  unix_hosts_file_path = '/etc/hosts'
  endpoints = {}
  
  if File.exist?(windows_hosts_file_path) then
    hosts_file_path = windows_hosts_file_path
  elsif File.exist?(unix_hosts_file_path) then
    hosts_file_path = unix_hosts_file_path
  else
    dual_log(level: :fatal, message: "No `hosts` file found at neither #{unix_hosts_file_path} nor #{windows_hosts_file_path}!")
  end
  
  File.foreach(hosts_file_path) do |line|
    if matches = line.downcase.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) +([a-z0-9\.\-]+) +# *Envoyant *: *(\d{1,5})\s*$/i) then
      _, ip, hostname, port = matches.to_a
      endpoints[hostname] = "#{ip}:#{port}"
    end
  end
  
  endpoints_string = endpoints.map{next "#{_1[0]} => #{_1[1]}"}.join("\r\n")
  
  if endpoints.any? then
    dual_log(level: :info, message: "Parsed endpoints from hosts file:\r\n#{endpoints_string}")
  else
    dual_log(level: :fatal, message: <<~TUTORIAL)
      No endpoints were found defined in your `hosts` file at: #{hosts_file_path}
    
      To define endpoints, add lines to your hosts file in the following format:
      ip hostname # Envoyant: port
      The comment marker must be `# Envoyant:` followed by the port number.
    
      Examples:
      127.0.0.1    comfyui.local                      # Envoyant: 8188
      192.168.0.10 sillytavern                        # Envoyant: 8000
      172.16.0.2   searx.instance                     # Envoyant: 8888
      127.0.1.1    bush.did                           # Envoyant: 911
      10.11.1.22                     fed.gov.elon.god # Envoyant: 1337
      78.0.20.100  ayy.lmao.co.uk.su.fed.gov.elon.god # Envoyant: 1337
      
      Then access it in your Web browser like this after starting Envoyant:
      http://comfyui.local
      This would become equivalent to accessing:
      http://127.0.0.1:8188
    TUTORIAL
  end
  
  return endpoints
end

def make_ports_string(client_socket: nil, backend_socket: nil, towards: :both)
  direction_char = {client: '<=-', backend: '-=>', both: '<=>'}
  ports_string = ''
  ports_string += client_socket.remote_address.ip_port.to_s if client_socket && !client_socket.closed?
  ports_string += direction_char[towards]
  ports_string += backend_socket.remote_address.ip_port.to_s if backend_socket && !backend_socket.closed?
  
  return ports_string
end

def dual_log(level: :info, message: '', headers: '', body: '')
  thread_label = Thread.current.native_thread_id
  file_message = "[#{thread_label}] #{message}\r\n#{headers}#{body}\r\n"
  
  if body.empty? then
    terminal_message = file_message
  else
    body_size = body.bytesize
    body_hash = Zlib::adler32(body).to_s(16)
    terminal_message = "[#{thread_label}] #{message}\r\n#{headers}Body: #{body_size} bytes. Hash: #{body_hash}\r\n"
  end
  
  FILE_LOGGER.send(level, file_message)
  TERMINAL_LOGGER.send(level, terminal_message)
  
  return nil
end

def handle_client(client_socket, keepalive)
  begin
    backend_socket = nil
    
    loop do
      request_headers = ''
      while line = client_socket.gets
        raise 'Nil read inside client headers!' if line.nil?
        request_headers += line
        break if line == "\r\n"
      end
      
      request_content_length = request_headers[/Content-Length: (\d+)/i, 1]
      request_body = ''
      
      if request_content_length then
        request_body = client_socket.read(request_content_length.to_i).to_s
      end
      
      request = request_headers + request_body
      ports_string = make_ports_string(client_socket: client_socket, backend_socket: backend_socket, towards: :backend)
      dual_log(level: :debug, message: "Processing request #{ports_string}:", headers: request_headers, body: request_body)
      host_match = request_headers[/Host: (\S+)/i, 1]
      backend_uri = ENDPOINTS[host_match]
      
      unless backend_uri then
        client_socket.write "HTTP/1.1 404 Not Found\r\n\r\n"
        ports_string = make_ports_string(client_socket: client_socket, backend_socket: backend_socket, towards: :backend)
        dual_log(level: :error, message: "No backend hostname '#{host_match}' found for #{ports_string}", headers: request_headers)
        raise 'Aborting thread.'
      end
      
      backend_ip, backend_port = backend_uri.split(?:)
      backend_socket = TCPSocket.new(backend_ip, backend_port)
      backend_socket.binmode
      proxied_request_headers = request_headers.gsub(host_match, "#{backend_ip}:#{backend_port}")
      proxied_request_body = request_body
      
      unless keepalive || proxied_request_headers.match(/Upgrade: websocket/i) then
        if proxied_request_headers.match(/Connection:/i) then
          proxied_request_headers.gsub!(/Connection:.*$/i, "Connection: close\r")
        else
          proxied_request_headers.sub!(/\r\n\r\n\z/, "Connection: close\r\n\r\n")
        end
      end
      
      backend_socket.write(proxied_request_headers, proxied_request_body)
      ports_string = make_ports_string(client_socket: client_socket, backend_socket: backend_socket, towards: :backend)
      dual_log(level: :info, message: "Relayed request #{ports_string}:", headers: proxied_request_headers, body: proxied_request_body)
      response_headers = ''
      
      while line = backend_socket.gets
        raise 'Nil read in response headers!' if line.nil?
        response_headers += line
        break if line == "\r\n"
      end
      
      client_socket.write(response_headers)
      
      if response_headers.match(/Upgrade: websocket/i) then
        ports_string = make_ports_string(client_socket: client_socket, backend_socket: backend_socket, towards: :client)
        dual_log(level: :info, message: "WebSocket upgrade #{ports_string}", headers: response_headers)
        
        Thread.new do
          begin
            loop do
              response_body = backend_socket.recv(65536)
              client_socket.write(response_body)
              ports_string = make_ports_string(client_socket: client_socket, backend_socket: backend_socket, towards: :client)
              dual_log(level: :info, message: "Relayed WebSocket message #{ports_string}:", body: response_body)
            end
          rescue Errno::ECONNABORTED, Errno::ECONNRESET, IOError
            ports_string = make_ports_string(client_socket: client_socket, backend_socket: backend_socket, towards: :client)
            dual_log(level: :info, message: "Backend WebSocket connection closed #{ports_string}.")
          ensure
            backend_socket.close rescue nil
            client_socket.close rescue nil
            Thread.current.kill
          end
        end
        
        begin
          loop do
            request_body = client_socket.recv(65536)
            backend_socket.write(request_body)
            ports_string = make_ports_string(client_socket: client_socket, backend_socket: backend_socket, towards: :backend)
            dual_log(level: :info, message: "Relayed WebSocket message #{ports_string}:", body: request_body)
          end
        rescue Errno::ECONNABORTED, Errno::ECONNRESET, IOError
          ports_string = make_ports_string(client_socket: client_socket, backend_socket: backend_socket, towards: :backend)
          dual_log(level: :info, message: "Client WebSocket connection closed #{ports_string}.")
        ensure
          backend_socket.close rescue nil
          client_socket.close rescue nil
          Thread.current.kill
        end
      elsif response_headers.match(/Transfer-Encoding: chunked/i) then
        response_body = ''
        
        while true
          line = backend_socket.gets
          response_body += line
          raise 'Nil read in chunk header!' if line.nil?
          chunk_size = line.strip.hex
          chunk_data = backend_socket.read(chunk_size)
          response_body += chunk_data
          crlf = backend_socket.gets
          raise 'Nil read in chunk CRLF!' if line.nil?
          response_body += crlf
          ports_string = make_ports_string(client_socket: client_socket, backend_socket: backend_socket, towards: :client)
          dual_log(level: :warn, message: "Relaying malformed chunk terminator #{ports_string}:", headers: response_headers, body: response_body) unless crlf.match(/^\r\n$/)
          break if chunk_size == 0
        end
      elsif length_string = response_headers[/Content-Length: (\d+)/i, 1] then
        length_integer = length_string.to_i
        response_body = backend_socket.read(length_integer).to_s
        raise "Response body over declared length #{length_integer}" if response_body.size > length_integer
      elsif response_headers.match(/Connection: close/i) then
        response_body = backend_socket.read.to_s
        ports_string = make_ports_string(client_socket: client_socket, backend_socket: backend_socket, towards: :client)
        dual_log(level: :debug, message: "Relaying full indeterminate body format #{ports_string}:", headers: response_headers, body: response_body)
      elsif [*100..199, 204, 304].include?(response_headers.lines.first[/^HTTP\/1\.1 (\d{3})/, 1].to_i) || proxied_request_headers.match(/^HEAD/) then
        response_body = ''
        ports_string = make_ports_string(client_socket: client_socket, backend_socket: backend_socket, towards: :client)
        dual_log(level: :debug, message: "Relaying a response without a body #{ports_string}:", headers: response_headers, body: response_body)
      else
        response_body = backend_socket.recv(65535).to_s
        ports_string = make_ports_string(client_socket: client_socket, backend_socket: backend_socket, towards: :client)
        dual_log(level: :warn, message: "Relaying up to 64KB of indeterminate body format #{ports_string}:", headers: response_headers, body: response_body)
      end
      
      client_socket.write(response_body)
      ports_string = make_ports_string(client_socket: client_socket, backend_socket: backend_socket, towards: :client)
      dual_log(level: :info, message: "Relayed response #{ports_string}:", headers: response_headers, body: response_body)
      all_headers = proxied_request_headers + response_headers
      break if all_headers.match(/Connection: close/i)
    end
  rescue => e
    ports_string = make_ports_string(client_socket: client_socket, backend_socket: backend_socket, towards: :both)
    dual_log(level: :error, message: "Error handling connection #{ports_string}: #{e.message}", headers: e.backtrace.join("\r\n") + "\r\n")
  ensure
    client_socket.close rescue nil
    backend_socket.close rescue nil
  end
  
  return nil
end

ENDPOINTS = parse_hosts_file

options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} [options]"
  opts.on('-k', '--keep-dead', 'Suppress keep-alive connections.') do |keep_dead|
    options[:keepalive] = false
  end
end.parse!

keepalive = options.fetch(:keepalive, true)
server = TCPServer.new('0.0.0.0', 80)
server.binmode
dual_log(level: :info, message: "Reverse proxy listening on port #{server.local_address.ip_port}")

if keepalive then
  dual_log(level: :info, message: 'Keep-alive will be allowed.')
else
  dual_log(level: :info, message: 'Keep-alive will be suppressed.')
end

trap("INT") do
  server.close rescue nil
  FILE_LOGGER.close rescue nil
  TERMINAL_LOGGER.close rescue nil
  exit(0)
end

loop do
  client_socket = server.accept
  client_socket.binmode
  Thread.new(client_socket, keepalive) do |socket|
    handle_client(socket, keepalive)
  end
end

FILE_LOGGER.close rescue nil
TERMINAL_LOGGER.close rescue nil

# Todo:
# E, [2025-09-05T18:16:07.664079 #2224] ERROR -- : [34952] No backend hostname '' found for 50723-=>8000
# 
# E, [2025-09-05T18:16:07.664243 #2224] ERROR -- : [34952] Error handling connection 50723<=>8000: Aborting thread.
# G:/Projects/rb/Envoyant/main.rb:143:in `block in handle_client'
# G:/Projects/rb/Envoyant/main.rb:118:in `loop'
# G:/Projects/rb/Envoyant/main.rb:118:in `handle_client'
# G:/Projects/rb/Envoyant/main.rb:294:in `block (2 levels) in <main>'
