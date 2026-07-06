# encoding: utf-8
CERTS_DIR = File.expand_path('../fixtures/certs/generated', File.dirname(__FILE__))

def certificate_path(filename)
  File.join(CERTS_DIR, filename)
end

RSpec.configure do |config|
  config.formatter = :documentation
end

##
# yield the block with a port that is available
# @return [Integer]: a port that is available
def find_available_port(host:"::")
  with_bound_port(host: host, &:itself)
end

##
# Yields block with a port that is unavailable
# @yieldparam port [Integer]
# @yieldreturn [Object]
# @return [Object]
def with_bound_port(host:"::", port:0, &block)
  server = TCPServer.new(host, port)

  return yield(server.local_address.ip_port)
ensure
  server&.close
end