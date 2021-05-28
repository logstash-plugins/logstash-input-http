require "logstash/devutils/rspec/spec_helper"
require "logstash/devutils/rspec/shared_examples"
require "logstash/inputs/http"
require "json"
require "manticore"
require "stud/temporary"
require "zlib"
require "stringio"
require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'

java_import "io.netty.handler.ssl.util.SelfSignedCertificate"

describe LogStash::Inputs::Http do

  before do
    srand(RSpec.configuration.seed)
  end

  let(:client) { Manticore::Client.new(client_options) }
  let(:client_options) { { } }
  let(:logstash_queue) { Queue.new }
  let(:port) { rand(5000) + 1025 }

  it_behaves_like "an interruptible input plugin" do
    let(:config) { { "port" => port } }
  end

  after :each do
    client.clear_pending
    client.close
    subject.stop
  end

  describe "request handling" do
    subject { LogStash::Inputs::Http.new("port" => port) }

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

      subject { described_class.new("port" => port, "threads" => threads, "max_pending_requests" => max_pending_requests) }

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
      subject { LogStash::Inputs::Http.new("port" => port) }
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
          response = client.post("http://127.0.0.1:#{port}/meh.json",
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
      subject { LogStash::Inputs::Http.new("port" => port, "codec" => "json") }
      it "should parse the json body" do
        response = client.post("http://127.0.0.1:#{port}/meh.json", :body => { "message" => "Hello" }.to_json).call
        event = logstash_queue.pop
        expect(event.get("message")).to eq("Hello")
      end
    end

    context "with json_lines codec without final delimiter" do
      subject { LogStash::Inputs::Http.new("port" => port, "codec" => "json_lines") }
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
  def setup_server_client
    subject.register
    t = Thread.new { subject.run(logstash_queue) }
    ok = false
    until ok
      begin
        client.post("http://127.0.0.1:#{port}", :body => '{}').call
      rescue => e
        # retry
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

  context "with :ssl => false" do
    subject { LogStash::Inputs::Http.new("port" => port, "ssl" => false) }
    it "should not raise exception" do
      expect { subject.register }.to_not raise_exception
    end
  end
  context "with :ssl => true" do
    context "without :ssl_certificate" do
      subject { LogStash::Inputs::Http.new("port" => port, "ssl" => true) }
      it "should raise exception" do
        expect { subject.register }.to raise_exception(LogStash::ConfigurationError)
      end
    end
    context "with :ssl_certificate" do
      let(:ssc) { SelfSignedCertificate.new }
      let(:ssl_certificate) { ssc.certificate }
      let(:ssl_key) { ssc.private_key }

      let(:config) do
        { "port" => port, "ssl" => true, "ssl_certificate" => ssl_certificate.path, "ssl_key" => ssl_key.path }
      end

      after(:each) { ssc.delete }

      subject { LogStash::Inputs::Http.new(config) }

      it "should not raise exception" do
        expect { subject.register }.to_not raise_exception
      end

      context "with ssl_verify_mode = none" do
        subject { LogStash::Inputs::Http.new(config.merge("ssl_verify_mode" => "none")) }

        it "should not raise exception" do
          expect { subject.register }.to_not raise_exception
        end
      end
      ["peer", "force_peer"].each do |verify_mode|
        context "with ssl_verify_mode = #{verify_mode}" do
          subject { LogStash::Inputs::Http.new("port" => port, "ssl" => true,
                                               "ssl_certificate" => ssl_certificate.path,
                                               "ssl_certificate_authorities" => ssl_certificate.path,
                                               "ssl_key" => ssl_key.path,
                                               "ssl_verify_mode" => verify_mode
                                              ) }
          it "should not raise exception" do
            expect { subject.register }.to_not raise_exception
          end
        end
      end
      context "with verify_mode = none" do
        subject { LogStash::Inputs::Http.new(config.merge("verify_mode" => "none")) }

        it "should not raise exception" do
          expect { subject.register }.to_not raise_exception
        end
      end
      ["peer", "force_peer"].each do |verify_mode|
        context "with verify_mode = #{verify_mode}" do
          subject { LogStash::Inputs::Http.new("port" => port, "ssl" => true,
                                               "ssl_certificate" => ssl_certificate.path,
                                               "ssl_certificate_authorities" => ssl_certificate.path,
                                               "ssl_key" => ssl_key.path,
                                               "verify_mode" => verify_mode
                                              ) }
          it "should not raise exception" do
            expect { subject.register }.to_not raise_exception
          end
        end
      end

      context "with invalid cipher_suites" do
        let(:config) { super().merge("cipher_suites" => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA38") }

        it "should raise a configuration error" do
          expect( subject.logger ).to receive(:error) do |msg, opts|
            expect( msg ).to match /.*?configuration invalid/
            expect( opts[:message] ).to match /TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA38.*? not available/
          end
          expect { subject.register }.to raise_error(LogStash::ConfigurationError)
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
          super().merge("ssl_verify_mode" => "peer",
                      "ssl_certificate_authorities" => [ ssc.certificate.path, ssc.private_key.path ])
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

    end
  end
end
