require "logstash/devutils/rspec/spec_helper"
require "logstash/devutils/rspec/shared_examples"
require "logstash/inputs/http"
require "json"
require "manticore"
require "stud/temporary"
require "zlib"
require "stringio"
require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'
require 'inputs/helpers'

java_import "io.netty.handler.ssl.util.SelfSignedCertificate"

describe LogStash::Inputs::Http do

  before do
    srand(RSpec.configuration.seed)
  end

  let(:client) { Manticore::Client.new(client_options) }
  let(:client_options) { { } }
  let(:logstash_queue) { Queue.new }
  let(:port) { rand(5000) + 1025 }
  let(:url) { "http://127.0.0.1:#{port}" }

  let(:config) { { "port" => port } }

  subject { described_class.new(config) }

  it_behaves_like "an interruptible input plugin" do
    let(:config) { { "port" => port } }
  end

  after :each do
    client.clear_pending
    client.close
    subject.stop
  end

  describe "request handling" do

    before :each do
      setup_server_client
    end

    describe "handling overflowing requests with a 429" do
      let(:logstash_queue_size) { rand(10) + 1 }
      let(:max_pending_requests) { rand(5) + 1 }
      let(:threads) { rand(4) + 1 }
      let(:logstash_queue) { SizedQueue.new(logstash_queue_size) }
      let(:client_options) { {
        "request_timeout" => 0.1,
        "connect_timeout" => 3,
        "socket_timeout" => 0.1
      } }

      let(:config) { { "port" => port, "threads" => threads, "max_pending_requests" => max_pending_requests } }

      context "when sending more requests than queue slots" do
        it "should block when the queue is full" do
          # these will queue and return 200
          logstash_queue_size.times.each do |i|
            response = client.post("http://127.0.0.1:#{port}", :body => '{}').call
            expect(response.code).to eq(200)
          end

          # these will block
          (threads + max_pending_requests).times.each do |i|
            expect {
              client.post("http://127.0.0.1:#{port}", :body => '{}').call
            }.to raise_error(Manticore::SocketTimeout)
          end

          # by now we should be rejecting with 429
          response = client.post("http://127.0.0.1:#{port}", :body => '{}').call
          expect(response.code).to eq(429)
        end
      end
    end

    context "with default codec" do

      context "when receiving a text/plain request" do
        it "should process the request normally" do
          client.post("http://127.0.0.1:#{port}/meh.json",
                      :headers => { "content-type" => "text/plain" },
                      :body => "hello").call
          event = logstash_queue.pop
          expect(event.get("message")).to eq("hello")
        end
      end

      context "when receiving a deflate compressed text/plain request" do
        it "should process the request normally" do
          client.post("http://127.0.0.1:#{port}/meh.json",
                      :headers => { "content-type" => "text/plain", "content-encoding" => "deflate" },
                      :body => Zlib::Deflate.deflate("hello")).call
          event = logstash_queue.pop
          expect(event.get("message")).to eq("hello")
        end
      end

      context "when receiving a deflate text/plain request that cannot be decompressed" do
        let(:response) do
          client.post("http://127.0.0.1:#{port}/meh.json",
                      :headers => { "content-type" => "text/plain", "content-encoding" => "deflate" },
                      :body => "hello").call
        end
        it "should respond with 400" do
          expect(response.code).to eq(400)
        end
      end

      context "when receiving a gzip compressed text/plain request" do
        it "should process the request normally" do
          wio = StringIO.new("w")
          z = Zlib::GzipWriter.new(wio)
          z.write("hello")
          z.close
          entity = org.apache.http.entity.ByteArrayEntity.new(wio.string.to_java_bytes)
          response = client.post("http://127.0.0.1:#{port}",
                      :headers => { "Content-Encoding" => "gzip" },
                      :entity => entity).call
          expect(response.code).to eq(200)
          event = logstash_queue.pop
          expect(event.get("message")).to eq("hello")
        end
      end

      context "when receiving a gzip text/plain request that cannot be decompressed" do
        let(:response) do
          client.post("http://127.0.0.1:#{port}",
                      :headers => { "Content-Encoding" => "gzip" },
                      :body => Zlib::Deflate.deflate("hello")).call
        end
        it "should respond with 400" do
          expect(response.code).to eq(400)
        end
      end

      context "when receiving an application/json request" do
        it "should parse the json body" do
          client.post("http://127.0.0.1:#{port}/meh.json",
                      :headers => { "content-type" => "application/json" },
                      :body => { "message_body" => "Hello" }.to_json).call
          event = logstash_queue.pop
          expect(event.get("message_body")).to eq("Hello")
        end
      end
    end

    context "with json codec" do
      let(:config) { super().merge("codec" => "json") }
      let(:url) { "http://127.0.0.1:#{port}/meh.json" }
      let(:response) do
        client.post(url, :body => { "message" => "Hello" }.to_json).call
      end

      it "should parse the json body" do
        expect(response.code).to eq(200)
        event = logstash_queue.pop
        expect(event.get("message")).to eq("Hello")
      end

      context 'with ssl' do

        let(:url) { super().sub('http://', 'https://') }

        let(:config) do
          super().merge 'ssl_enabled' => true,
                        'ssl_certificate_authorities' => [certificate_path('root.crt')],
                        'ssl_certificate' => certificate_path( 'server_from_root.crt'),
                        'ssl_key' => certificate_path( 'server_from_root.key.pkcs8'),
                        'ssl_client_authentication' => 'optional'
        end

        let(:client_options) do
          super().merge ssl: {
              verify: false,
              ca_file: certificate_path( 'root.crt'),
              client_cert: certificate_path( 'client_from_root.crt'),
              client_key: certificate_path( 'client_from_root.key.pkcs8'),
          }
        end

        it "should parse the json body" do
          # [DEBUG][io.netty.handler.ssl.SslHandler] [id: 0xcaf869ff, L:/127.0.0.1:5610 - R:/127.0.0.1:32890] HANDSHAKEN: protocol:TLSv1.2 cipher suite:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
          # [DEBUG][org.apache.http.conn.ssl.SSLConnectionSocketFactory] Secure session established
          # [DEBUG][org.apache.http.conn.ssl.SSLConnectionSocketFactory]  negotiated protocol: TLSv1.2
          # [DEBUG][org.apache.http.conn.ssl.SSLConnectionSocketFactory]  negotiated cipher suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
          expect(response.code).to eq(200)
          event = logstash_queue.pop
          expect(event.get("message")).to eq("Hello")
        end

        TLS13_ENABLED_BY_DEFAULT = begin
                                     context = javax.net.ssl.SSLContext.getInstance('TLS')
                                     context.init nil, nil, nil
                                     context.getDefaultSSLParameters.getProtocols.include? 'TLSv1.3'
                                   rescue => e
                                     warn "failed to detect TLSv1.3 support: #{e.inspect}"
                                     nil
                                   end

        context 'with TLSv1.3 client' do

          let(:client_options) do
            super().tap do |opts|
              opts.fetch(:ssl).merge! protocols: ['TLSv1.3']
            end
          end

          it "should parse the json body" do
            expect(response.code).to eq(200)
            event = logstash_queue.pop
            expect(event.get("message")).to eq("Hello")
          end

          context 'enforced TLSv1.3 in plugin' do

            let(:config) { super().merge 'ssl_supported_protocols' => ['TLSv1.3'],
                                         'ssl_cipher_suites' => [ 'TLS_AES_128_GCM_SHA256' ] }

            it "should parse the json body" do
              expect(response.code).to eq(200)
              event = logstash_queue.pop
              expect(event.get("message")).to eq("Hello")
            end

          end

          context 'enforced TLSv1.3 (deprecated options)' do

            let(:config) { super().merge 'tls_min_version' => 1.3,
                                         'cipher_suites' => [ 'TLS_AES_128_GCM_SHA256' ] }

            it "should parse the json body" do
              expect(response.code).to eq(200)
              event = logstash_queue.pop
              expect(event.get("message")).to eq("Hello")
            end

          end

        end if TLS13_ENABLED_BY_DEFAULT

      end

    end

    context "with json_lines codec without final delimiter" do
      let(:config) { super().merge("codec" => "json_lines") }
      let(:line1) { '{"foo": 1}' }
      let(:line2) { '{"foo": 2}' }
      it "should parse all json_lines in body including last one" do
        client.post("http://localhost:#{port}/meh.json", :body => "#{line1}\n#{line2}").call
        expect(logstash_queue.size).to eq(2)
        event = logstash_queue.pop
        expect(event.get("foo")).to eq(1)
        event = logstash_queue.pop
        expect(event.get("foo")).to eq(2)
      end
    end

    context "when using a custom codec mapping" do
      subject { LogStash::Inputs::Http.new("port" => port,
                                           "additional_codecs" => { "application/json" => "plain" }) }
      it "should decode the message accordingly" do
        body = { "message" => "Hello" }.to_json
        client.post("http://127.0.0.1:#{port}/meh.json",
                    :headers => { "content-type" => "application/json" },
                    :body => body).call
        event = logstash_queue.pop
        expect(event.get("message")).to eq(body)
      end
    end
    
    context "when receiving a content-type with a charset" do
      subject { LogStash::Inputs::Http.new("port" => port,
                                           "additional_codecs" => { "application/json" => "plain" }) }
      it "should decode the message accordingly" do
        body = { "message" => "Hello" }.to_json
        client.post("http://127.0.0.1:#{port}/meh.json",
                    :headers => { "content-type" => "application/json; charset=utf-8" },
                      :body => body).call
        event = logstash_queue.pop
        expect(event.get("message")).to eq(body)
      end
    end

    context "when using custom headers" do
      let(:custom_headers) { { 'access-control-allow-origin' => '*' } }
      subject { LogStash::Inputs::Http.new("port" => port, "response_headers" => custom_headers) }

      describe "the response" do
        it "should include the custom headers" do
          response = client.post("http://127.0.0.1:#{port}/meh", :body => "hello").call
          expect(response.headers.to_hash).to include(custom_headers)
        end
      end
    end
    describe "basic auth" do
      user = "test"; password = "pwd"
      subject { LogStash::Inputs::Http.new("port" => port, "user" => user, "password" => password) }
      let(:auth_token) { Base64.strict_encode64("#{user}:#{password}") }
      context "when client doesn't present auth token" do
        let!(:response) { client.post("http://127.0.0.1:#{port}/meh", :body => "hi").call }
        it "should respond with 401" do
          expect(response.code).to eq(401)
        end
        it 'should include a WWW-Authenticate: Basic header' do
          expect(response['WWW-Authenticate']).to_not be_nil

          expect(response['WWW-Authenticate']).to start_with('Basic realm=')
        end
        it "should not generate an event" do
          expect(logstash_queue).to be_empty
        end
      end
      context "when client presents incorrect auth token" do
        let!(:response) do
          client.post("http://127.0.0.1:#{port}/meh",
                      :headers => {
                        "content-type" => "text/plain",
                        "authorization" => "Basic meh"
                      },
                      :body => "hi").call
        end
        it "should respond with 401" do
          expect(response.code).to eq(401)
        end
        it 'should not include a WWW-Authenticate header' do
          expect(response['WWW-Authenticate']).to be_nil
        end
        it "should not generate an event" do
          expect(logstash_queue).to be_empty
        end
      end
      context "when client presents correct auth token" do
        let!(:response) do
          client.post("http://127.0.0.1:#{port}/meh",
                      :headers => {
                        "content-type" => "text/plain",
                        "authorization" => "Basic #{auth_token}"
                      }, :body => "hi").call
        end
        it "should respond with 200" do
          expect(response.code).to eq(200)
        end
        it "should generate an event" do
          expect(logstash_queue).to_not be_empty
        end
      end
    end

    describe "HTTP Protocol Handling" do
      context "when an HTTP1.1 request is made" do
        let(:protocol_version) do
          Java::OrgApacheHttp::HttpVersion::HTTP_1_1
        end
        it "responds with a HTTP1.1 response" do
          response = client.post("http://127.0.0.1:#{port}", :body => "hello")
          response.request.set_protocol_version(protocol_version)
          response.call
          response_protocol_version = response.instance_variable_get(:@response).get_protocol_version
          expect(response_protocol_version).to eq(protocol_version)
        end
      end
      context "when an HTTP1.0 request is made" do
        let(:protocol_version) do
          Java::OrgApacheHttp::HttpVersion::HTTP_1_0
        end
        it "responds with a HTTP1.0 response" do
          response = client.post("http://127.0.0.1:#{port}", :body => "hello")
          response.request.set_protocol_version(protocol_version)
          response.call
          response_protocol_version = response.instance_variable_get(:@response).get_protocol_version
          expect(response_protocol_version).to eq(protocol_version)
        end
      end
    end
    describe "return code" do
      it "responds with a 200" do
        response = client.post("http://127.0.0.1:#{port}", :body => "hello")
        response.call
        expect(response.code).to eq(200)
      end
      context "when response_code is configured" do
        let(:code) { 202 }
        subject { LogStash::Inputs::Http.new("port" => port, "response_code" => code) }
        it "responds with the configured code" do
          response = client.post("http://127.0.0.1:#{port}", :body => "hello")
          response.call
          expect(response.code).to eq(202)
        end
      end
    end
  end

  describe "ECS support", :ecs_compatibility_support, :aggregate_failures do
    ecs_compatibility_matrix(:disabled, :v1) do |ecs_select|
      let(:host_field) { ecs_select[disabled: "[host]", v1: "[host][ip]"] }
      let(:header_field) { ecs_select[disabled: "headers", v1: "[@metadata][input][http][request][headers]"] }
      let(:http_version_field) { ecs_select[disabled: "[headers][http_version]", v1: "[http][version]"] }
      let(:user_agent_field) { ecs_select[disabled: "[headers][http_user_agent]", v1: "[user_agent][original]"] }
      let(:http_host_field) { "[headers][http_host]" }
      let(:domain_field) { "[url][domain]" }
      let(:port_field) { "[url][port]" }
      let(:request_method_field) { ecs_select[disabled: "[headers][request_method]", v1: "[http][method]"] }
      let(:request_path_field) { ecs_select[disabled: "[headers][request_path]", v1: "[url][path]"] }
      let(:content_length_field) { ecs_select[disabled: "[headers][content_length]", v1: "[http][request][body][bytes]"] }
      let(:content_type_field) { ecs_select[disabled: "[headers][content_type]", v1: "[http][request][mime_type]"] }

      before :each do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
        setup_server_client
      end

      describe "remote host" do
        subject { LogStash::Inputs::Http.new(config.merge("port" => port)) }
        context "by default" do
          let(:config) { {} }
          it "is written to the \"host\" field" do
            client.post("http://localhost:#{port}/meh.json",
                        :headers => { "content-type" => "text/plain" },
                        :body => "hello").call
            event = logstash_queue.pop
            expect(event.get(host_field)).to eq("127.0.0.1")
          end
        end

        context "when using remote_host_target_field" do
          let(:config) { { "remote_host_target_field" => "remote_host" } }
          it "is written to the value of \"remote_host_target_field\" property" do
            client.post("http://localhost:#{port}/meh.json",
                        :headers => { "content-type" => "text/plain" },
                        :body => "hello").call
            event = logstash_queue.pop
            expect(event.get("remote_host")).to eq("127.0.0.1")
          end
        end
      end

      describe "request headers" do
        subject { LogStash::Inputs::Http.new(config.merge("port" => port)) }
        context "by default" do
          let(:config) { {} }
          it "are written to the \"headers\" field" do
            client.post("http://localhost:#{port}/meh.json",
                        :headers => { "content-type" => "text/plain" },
                        :body => "hello").call
            event = logstash_queue.pop
            expect(event.get(header_field)).to be_a(Hash)
            expect(event.get(request_method_field)).to eq("POST")
            expect(event.get(request_path_field)).to eq("/meh.json")
            expect(event.get(http_version_field)).to eq("HTTP/1.1")
            expect(event.get(user_agent_field)).to include("Manticore")
            if ecs_compatibility == :disabled
              expect(event.get(http_host_field)).to eq("localhost:#{port}")
            else
              expect(event.get(domain_field)).to eq("localhost")
              expect(event.get(port_field)).to eq(port)
            end

            expect(event.get(content_length_field)).to eq("5")
            expect(event.get(content_type_field)).to eq("text/plain")
          end
        end
        context "when using request_headers_target_field" do
          let(:config) { { "request_headers_target_field" => "request_headers" } }
          it "are written to the field set in \"request_headers_target_field\"" do
            client.post("http://localhost:#{port}/meh.json",
                        :headers => { "content-type" => "text/plain" },
                        :body => "hello").call
            event = logstash_queue.pop
            expect(event.get("request_headers")).to be_a(Hash)
            expect(event.get("request_headers")).to include("request_method" => "POST")
            expect(event.get("request_headers")).to include("request_path" => "/meh.json")
            expect(event.get("request_headers")).to include("http_version" => "HTTP/1.1")
            expect(event.get("request_headers")["http_user_agent"]).to include("Manticore")
            expect(event.get("request_headers")).to include("http_host" => "localhost:#{port}")
            expect(event.get("request_headers")).to include("content_length" => "5")
            expect(event.get("request_headers")).to include("content_type" => "text/plain")
          end
        end
      end
    end
  end

  # wait until server is ready
  def setup_server_client(url = self.url)
    subject.register
    t = Thread.start { subject.run(logstash_queue) }
    ok = false
    until ok
      begin
        client.post(url, :body => '{}').call
      rescue Manticore::SocketException => e
        puts "retry client.post due #{e}" if $VERBOSE
      rescue Manticore::ManticoreException => e
        warn e.inspect
        raise e.cause ? e.cause : e
      else
        ok = true
      end
      sleep 0.01
    end
    logstash_queue.pop if logstash_queue.size == 1 # pop test event
  end

  describe "parse domain host" do
    let(:localhost) { "localhost" }
    let(:ipv6) { "2001:db8::8a2e:370:7334" }

    it "should parse in IPV4 format with port" do
      domain, port = LogStash::Inputs::Http.get_domain_port("#{localhost}:8080")
      expect(domain).to eq(localhost)
      expect(port).to eq(8080)
    end

    it "should parse in IPV4 format without port" do
      domain, port = LogStash::Inputs::Http.get_domain_port(localhost)
      expect(domain).to eq(localhost)
      expect(port).to be_nil
    end

    it "should parse in IPV6 format with port" do
      domain, port = LogStash::Inputs::Http.get_domain_port("[#{ipv6}]:8080")
      expect(domain).to eq(ipv6)
      expect(port).to eq(8080)
    end

    it "should parse in IPV6 format without port" do
      domain, port = LogStash::Inputs::Http.get_domain_port("#{ipv6}")
      expect(domain).to eq(ipv6)
      expect(port).to be_nil
    end
  end

  context "with :ssl_enabled => false" do
    let(:config) { {"port" => port, "ssl_enabled" => false} }

    it "should not raise exception" do
      expect { subject.register }.to_not raise_exception
    end

    context "and `ssl_` settings provided" do
      let(:ssc) { SelfSignedCertificate.new }
      let(:config) { { "port" => 0, "ssl_enabled" => false, "ssl_certificate" => ssc.certificate.path, "ssl_client_authentication" => "none", "cipher_suites" => ["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"] } }

      it "should warn about not using the configs" do
        expect(subject.logger).to receive(:warn).with(/^Configured SSL settings are not used when `ssl_enabled` is set to `false`: \[("ssl_certificate"(,\s)?|"ssl_client_authentication"(,\s)?|"cipher_suites"(,\s)?)*\]$/)
        subject.register
      end
    end
  end

  context "with :ssl_enabled => true" do
    context "without :ssl_certificate" do
      subject { LogStash::Inputs::Http.new("port" => port, "ssl_enabled" => true) }
      it "should raise exception" do
        expect { subject.register }.to raise_exception(LogStash::ConfigurationError)
      end
    end
    context "with invalid cipher suites" do
      it "should raise a configuration error" do
        invalid_config = config.merge("ssl_cipher_suites" => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA38")
        expect { LogStash::Inputs::Http.new(invalid_config) }.to raise_error(LogStash::ConfigurationError)
      end
    end
    context "with :ssl_certificate" do
      let(:ssc) { SelfSignedCertificate.new }
      let(:ssl_certificate) { ssc.certificate }
      let(:ssl_key) { ssc.private_key }

      let(:config) do
        { "port" => port, "ssl_enabled" => true, "ssl_certificate" => ssl_certificate.path, "ssl_key" => ssl_key.path }
      end

      after(:each) { ssc.delete }

      subject { LogStash::Inputs::Http.new(config) }

      it "should not raise exception" do
        expect { subject.register }.to_not raise_exception
      end

      context "with ssl_verify_mode = none" do
        subject { LogStash::Inputs::Http.new(config.merge("ssl_client_authentication" => "none")) }

        it "should not raise exception" do
          expect { subject.register }.to_not raise_exception
        end
      end
      ["ssl_verify_mode", "verify_mode"].each do |config_name|
        ["peer", "force_peer"].each do |verify_mode|
          context "with deprecated #{config_name} = #{verify_mode}" do
            subject { LogStash::Inputs::Http.new("port" => port,
                                                 "ssl_enabled" => true,
                                                 "ssl_certificate" => ssl_certificate.path,
                                                 "ssl_certificate_authorities" => ssl_certificate.path,
                                                 "ssl_key" => ssl_key.path,
                                                  config_name => verify_mode
                                                ) }
            it "should not raise exception" do
              expect { subject.register }.to_not raise_exception
            end
          end
        end
      end
      ["ssl_verify_mode", "verify_mode"].each do |config_name|
        context "with deprecated #{config_name} = none" do
          subject { LogStash::Inputs::Http.new(config.merge(config_name => "none")) }

          it "should not raise exception" do
            expect { subject.register }.to_not raise_exception
          end
        end
      end
      context "with invalid ssl certificate" do
        before do
          cert = File.readlines path = config["ssl_certificate"]
          i = cert.index { |line| line.index('END CERTIFICATE') }
          cert[i - 1] = ''
          File.write path, cert.join("\n")
        end

        it "should raise a configuration error" do
          expect( subject.logger ).to receive(:error) do |msg, opts|
            expect( msg ).to match /SSL configuration invalid/
            expect( opts[:message] ).to match /File does not contain valid certificate/i
          end
          expect { subject.register }.to raise_error(LogStash::ConfigurationError)
        end
      end

      context "with invalid ssl key config" do
        let(:config) { super().merge("ssl_key_passphrase" => "1234567890") }

        it "should raise a configuration error" do
          expect( subject.logger ).to receive(:error) do |msg, opts|
            expect( msg ).to match /SSL configuration invalid/
            expect( opts[:message] ).to match /File does not contain valid private key/i
          end
          expect { subject.register }.to raise_error(LogStash::ConfigurationError)
        end
      end

      context "with invalid ssl certificate_authorities" do
        let(:config) do
          super().merge("ssl_client_authentication" => "optional", "ssl_certificate_authorities" => [ ssc.certificate.path, ssc.private_key.path ])
        end

        it "should raise a cert error" do
          expect( subject.logger ).to receive(:error) do |msg, opts|
            expect( msg ).to match(/SSL configuration failed/), lambda { "unexpected: logger.error #{msg.inspect}, #{opts.inspect}" }
            expect( opts[:message] ).to match /signed fields invalid/
          end
          begin
            subject.register
          rescue Java::JavaSecurityCert::CertificateParsingException
            :pass
          end
        end
      end

      context "with both verify_mode and ssl_verify_mode options set" do
        let(:config) do
          super().merge('verify_mode' => 'none', 'ssl_verify_mode' => 'none')
        end

        it "should raise a configuration error" do
          expect { subject.register }.to raise_error LogStash::ConfigurationError, /Use only .?ssl_verify_mode`.?/i
        end
      end

      context "with both ssl_client_authentication and ssl_verify_mode options set" do
        let(:config) do
          super().merge('ssl_client_authentication' => 'optional', 'ssl_verify_mode' => 'none')
        end

        it "should raise a configuration error" do
          expect { subject.register }.to raise_error LogStash::ConfigurationError, /Use only .?ssl_client_authentication.?/i
        end
      end

      context "with both ssl_client_authentication and verify_mode options set" do
        let(:config) do
          super().merge('ssl_client_authentication' => 'optional', 'verify_mode' => 'none')
        end

        it "should raise a configuration error" do
          expect { subject.register }.to raise_error LogStash::ConfigurationError, /Use only .?ssl_client_authentication.?/i
        end
      end

      context "with ssl_cipher_suites and cipher_suites set" do
        let(:config) do
          super().merge('ssl_cipher_suites' => ['TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'],
                        'cipher_suites' => ['TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'])
        end

        it "should raise a configuration error" do
          expect { subject.register }.to raise_error LogStash::ConfigurationError, /Use only .?ssl_cipher_suites.?/i
        end
      end

      context "with ssl_supported_protocols and tls_min_version set" do
        let(:config) do
          super().merge('ssl_supported_protocols' => ['TLSv1.2'], 'tls_min_version' => 1.0)
        end

        it "should raise a configuration error" do
          expect { subject.register }.to raise_error LogStash::ConfigurationError, /Use only .?ssl_supported_protocols.?/i
        end
      end

      context "with ssl_supported_protocols and tls_max_version set" do
        let(:config) do
          super().merge('ssl_supported_protocols' => ['TLSv1.2'], 'tls_max_version' => 1.2)
        end

        it "should raise a configuration error" do
          expect { subject.register }.to raise_error LogStash::ConfigurationError, /Use only .?ssl_supported_protocols.?/i
        end
      end

      context "with both ssl and ssl_enabled set" do
        let(:config) do
          super().merge('ssl' => true, 'ssl_enabled' => true )
        end

        it "should raise a configuration error" do
          expect { subject.register }.to raise_error LogStash::ConfigurationError, /Use only .?ssl_enabled.?/i
        end
      end

      context "with ssl_client_authentication" do
        context "normalized from ssl_verify_mode 'none'" do
          let(:config) { super().merge("ssl_verify_mode" => "none") }

          it "should transform the value to 'none'" do
            subject.register
            expect(subject.params).to match hash_including("ssl_client_authentication" => "none")
            expect(subject.instance_variable_get(:@ssl_client_authentication)).to eql("none")
          end

          context "and ssl_certificate_authorities is set" do
            let(:config) { super().merge("ssl_certificate_authorities" => [certificate_path( 'root.crt')]) }
            it "raise a configuration error" do
              expect { subject.register }.to raise_error(LogStash::ConfigurationError, "The configuration of `ssl_certificate_authorities` requires setting `ssl_verify_mode` to `peer` or 'force_peer'")
            end
          end
        end

        [%w[peer optional], %w[force_peer required]].each do |ssl_verify_mode, ssl_client_authentication|
          context "normalized from ssl_verify_mode '#{ssl_verify_mode}'" do
            let(:config) { super().merge("ssl_verify_mode" => ssl_verify_mode, "ssl_certificate_authorities" => [certificate_path( 'root.crt')]) }

            it "should transform the value to '#{ssl_client_authentication}'" do
              subject.register
              expect(subject.params).to match hash_including("ssl_client_authentication" => ssl_client_authentication)
              expect(subject.instance_variable_get(:@ssl_client_authentication)).to eql(ssl_client_authentication)
            end

            context "with no ssl_certificate_authorities set " do
              let(:config) { super().reject { |key| "ssl_certificate_authorities".eql?(key) } }
              it "raise a configuration error" do
                expect {subject.register}.to raise_error(LogStash::ConfigurationError, "Using `ssl_verify_mode` set to `peer` or `force_peer`, requires the configuration of `ssl_certificate_authorities`")
              end
            end
          end
        end

        context "configured to 'none'" do
          let(:config) { super().merge("ssl_client_authentication" => "none") }

          it "doesn't raise an error when certificate_authorities is not set" do
            expect {subject.register}.to_not raise_error
          end

          context "with certificate_authorities set" do
            let(:config) { super().merge("ssl_certificate_authorities" => [certificate_path( 'root.crt')]) }

            it "raise a configuration error" do
              expect {subject.register}.to raise_error(LogStash::ConfigurationError, "The configuration of `ssl_certificate_authorities` requires setting `ssl_client_authentication` to `optional` or 'required'")
            end
          end
        end

        context "configured to 'required'" do
          let(:config) { super().merge("ssl_client_authentication" => "required") }

          it "raise a ConfigurationError when certificate_authorities is not set" do
            expect {subject.register}.to raise_error(LogStash::ConfigurationError, "Using `ssl_client_authentication` set to `optional` or `required`, requires the configuration of `ssl_certificate_authorities`")
          end

          context "with ssl_certificate_authorities set" do
            let(:config) { super().merge("ssl_certificate_authorities" => [certificate_path( 'root.crt')]) }

            it "doesn't raise a configuration error" do
              expect {subject.register}.not_to raise_error
            end
          end
        end

        context "configured to 'optional'" do
          let(:config) { super().merge("ssl_client_authentication" => "optional") }

          it "raise a ConfigurationError when certificate_authorities is not set" do
            expect {subject.register}.to raise_error(LogStash::ConfigurationError, "Using `ssl_client_authentication` set to `optional` or `required`, requires the configuration of `ssl_certificate_authorities`")
          end

          context "with certificate_authorities set" do
            let(:config) { super().merge("ssl_certificate_authorities" => [certificate_path( 'root.crt')]) }

            it "doesn't raise a configuration error" do
              expect {subject.register}.not_to raise_error
            end
          end
        end
      end
    end
  end
end

# If we have a setting called `pipeline.ecs_compatibility`, we need to
# ensure that our additional_codecs are instantiated with the proper
# execution context in order to ensure that the pipeline setting is
# respected.
if LogStash::SETTINGS.registered?('pipeline.ecs_compatibility')

  def setting_value_supported?(name, value)
    setting = ::LogStash::SETTINGS.clone.get_setting(name)
    setting.set(value)
    setting.validate_value
    true
  rescue
    false
  end

  describe LogStash::Inputs::Http do
    context 'additional_codecs' do
      let(:port) { rand(1025...5000) }

      %w(disabled v1 v8).each do |spec|
        if setting_value_supported?('pipeline.ecs_compatibility', spec)
          context "with `pipeline.ecs_compatibility: #{spec}`" do
            # Override DevUtils's `new_pipeline` default to inject pipeline settings that
            # are different than our global settings, so that we can validate the condition
            # where pipeline settings override global settings.
            def new_pipeline(config_parts, pipeline_id = :main, settings = pipeline_settings)
              super(config_parts, pipeline_id, settings)
            end

            let(:pipeline_settings) do
              ::LogStash::SETTINGS.clone.tap do |s|
                s.set('pipeline.ecs_compatibility', spec)
              end
            end

            it 'propagates the ecs_compatibility pipeline setting to the additional_codecs' do
              # Ensure plugins pick up pipeline-level setting over the global default.
              aggregate_failures('precondition') do
                expect(::LogStash::SETTINGS).to_not be_set('pipeline.ecs_compatibility')
                expect(pipeline_settings).to be_set('pipeline.ecs_compatibility')
              end

              input("input { http { port => #{port} additional_codecs => { 'application/json' => 'json' 'text/plain' => 'plain' } } }") do |pipeline, queue|
                http_input = pipeline.inputs.first
                aggregate_failures('initialization precondition') do
                  expect(http_input).to be_a_kind_of(described_class)
                  expect(http_input.execution_context&.pipeline&.settings&.to_hash).to eq(pipeline_settings.to_hash)
                end

                http_input.codecs.each do |key, value|
                  aggregate_failures("Codec for `#{key}`") do
                    expect(value.ecs_compatibility).to eq(spec.to_sym)
                  end
                end
              end
            end
          end
        end
      end

      it 'propagates the execution context from the input to the codecs' do
        input("input { http { port => #{port} } }") do |pipeline, queue|
          http_input = pipeline.inputs.first
          expect(http_input).to be_a_kind_of(described_class) # precondition

          http_input.codecs.each do |key, value|
            aggregate_failures("Codec for `#{key}`") do
              expect(value.execution_context).to be http_input.execution_context
            end
          end
        end
      end
    end
  end
end
