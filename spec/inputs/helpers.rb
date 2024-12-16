# encoding: utf-8
CERTS_DIR = File.expand_path('../fixtures/certs/generated', File.dirname(__FILE__))

def certificate_path(filename)
  File.join(CERTS_DIR, filename)
end

RSpec.configure do |config|
  config.formatter = :documentation
end
