require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/http"
require "json"
require "ftw"
require "stud/temporary"
require "zlib"
require "stringio"

describe LogStash::Inputs::Http do

  before do
    srand(RSpec.configuration.seed)
  end

  let(:agent) { FTW::Agent.new }
  let(:queue) { Queue.new }
  let(:port) { rand(5000) + 1025 }

  it_behaves_like "an interruptible input plugin" do
    let(:config) { { "port" => port } }
  end

  after :each do
    subject.stop
  end

  describe "request handling" do
    subject { LogStash::Inputs::Http.new(config) }

    before :each do
      subject.register
      t = Thread.new { subject.run(queue) }
      sleep 0.01 until subject.instance_variable_get(:@server).running == 0
    end

    describe "remote host" do
      context "by default" do
        let(:config) { {} }
        it "is written to the \"host\" field" do
          agent.post!("http://localhost:8080/meh.json",
                      :headers => { "content-type" => "text/plain" },
                      :body => "hello")
          event = queue.pop
          expect(event.get("host")).to eq("127.0.0.1")
        end
      end
      context "when using remote_host_target_field" do
        let(:config) { { "remote_host_target_field" => "remote_host" } }
        it "is written to the value of \"remote_host_target_field\" property" do
          agent.post!("http://localhost:8080/meh.json",
                      :headers => { "content-type" => "text/plain" },
                      :body => "hello")
          event = queue.pop
          expect(event.get("remote_host")).to eq("127.0.0.1")
        end
      end
    end

    describe "request headers" do
      context "by default" do
        let(:config) { {} }
        it "are written to the \"headers\" field" do
          agent.post!("http://localhost:8080/meh.json",
                      :headers => { "content-type" => "text/plain" },
                      :body => "hello")
          event = queue.pop
          expect(event.get("headers")).to be_a(Hash)
          expect(event.get("headers")).to include("request_method" => "POST")
        end
      end
      context "when using request_headers_target_field" do
        let(:config) { { "request_headers_target_field" => "request_headers" } }
        it "are written to the field set in \"request_headers_target_field\"" do
          agent.post!("http://localhost:8080/meh.json",
                      :headers => { "content-type" => "text/plain" },
                      :body => "hello")
          event = queue.pop
          expect(event.get("request_headers")).to be_a(Hash)
          expect(event.get("request_headers")).to include("request_method" => "POST")
        end
      end
    end

    context "with default codec" do
      subject { LogStash::Inputs::Http.new("port" => port) }
      context "when receiving a text/plain request" do
        it "should process the request normally" do
          agent.post!("http://localhost:#{port}/meh.json",
                      :headers => { "content-type" => "text/plain" },
                      :body => "hello")
          event = queue.pop
          expect(event.get("message")).to eq("hello")
        end
      end
      context "when receiving a deflate compressed text/plain request" do
        it "should process the request normally" do
          agent.post!("http://localhost:#{port}/meh.json",
                      :headers => { "content-type" => "text/plain", "content-encoding" => "deflate" },
                      :body => Zlib::Deflate.deflate("hello"))
          event = queue.pop
          expect(event.get("message")).to eq("hello")
        end
      end
      context "when receiving a deflate text/plain request that cannot be decompressed" do
        it "should respond with 400" do
          response = agent.post!("http://localhost:#{port}/meh.json",
                                 :headers => { "content-type" => "text/plain", "content-encoding" => "deflate" },
                                   :body => "hello")
          expect(response.status).to eq(400)
        end
        it "should respond with a decompression error" do
          response = agent.post!("http://localhost:#{port}/meh.json",
                                 :headers => { "content-type" => "text/plain", "content-encoding" => "deflate" },
                                   :body => "hello")
          expect(response.read_body).to eq("Failed to decompress body")
        end
      end
      context "when receiving a gzip compressed text/plain request" do
        it "should process the request normally" do
          z = StringIO.new ""
          w = Zlib::GzipWriter.new z
          w.write("hello")
          w.finish
          agent.post!("http://localhost:#{port}/meh.json",
                      :headers => { "content-type" => "text/plain", "content-encoding" => "gzip" },
                        :body => z.string)
          event = queue.pop
          expect(event.get("message")).to eq("hello")
        end
      end
      context "when receiving a gzip text/plain request that cannot be decompressed" do
        let(:response) do
          agent.post!("http://localhost:#{port}/meh.json",
                      :headers => { "content-type" => "text/plain", "content-encoding" => "gzip" },
                      :body => "hello")
        end
        it "should respond with 400" do
          expect(response.status).to eq(400)
        end
        it "should respond with a decompression error" do
          expect(response.read_body).to eq("Failed to decompress body")
        end
      end
      context "when receiving an application/json request" do
        it "should parse the json body" do
          agent.post!("http://localhost:#{port}/meh.json",
                      :headers => { "content-type" => "application/json" },
                      :body => { "message_body" => "Hello" }.to_json)
          event = queue.pop
          expect(event.get("message_body")).to eq("Hello")
        end
      end
    end
    context "with json codec" do
      subject { LogStash::Inputs::Http.new("port" => port, "codec" => "json") }
      it "should parse the json body" do
        agent.post!("http://localhost:#{port}/meh.json", :body => { "message" => "Hello" }.to_json)
        event = queue.pop
        expect(event.get("message")).to eq("Hello")
      end
    end

    context "when using a custom codec mapping" do
      subject { LogStash::Inputs::Http.new("port" => port,
                                           "additional_codecs" => { "application/json" => "plain" }) }
      it "should decode the message accordingly" do
        body = { "message" => "Hello" }.to_json
        agent.post!("http://localhost:#{port}/meh.json",
                    :headers => { "content-type" => "application/json" },
                      :body => body)
        event = queue.pop
        expect(event.get("message")).to eq(body)
      end
    end

    context "when using custom headers" do
      let(:custom_headers) { { 'access-control-allow-origin' => '*' } }
      subject { LogStash::Inputs::Http.new("port" => port, "response_headers" => custom_headers) }

      describe "the response" do
        it "should include the custom headers" do
          response = agent.post!("http://localhost:#{port}/meh", :body => "hello")
          expect(response.headers.to_hash).to include(custom_headers)
        end
      end
    end
    describe "basic auth" do
      user = "test"; password = "pwd"
      subject { LogStash::Inputs::Http.new("port" => port, "user" => user, "password" => password) }
      let(:auth_token) { Base64.strict_encode64("#{user}:#{password}") }
      context "when client doesn't present auth token" do
        let!(:response) { agent.post!("http://localhost:#{port}/meh", :body => "hi") }
        it "should respond with 401" do
          expect(response.status).to eq(401)
        end
        it "should not generate an event" do
          expect(queue).to be_empty
        end
      end
      context "when client presents incorrect auth token" do
        let!(:response) do
          agent.post!("http://localhost:#{port}/meh",
                      :headers => {
                        "content-type" => "text/plain",
                        "authorization" => "Basic meh"
                      },
                      :body => "hi")
        end
        it "should respond with 401" do
          expect(response.status).to eq(401)
        end
        it "should not generate an event" do
          expect(queue).to be_empty
        end
      end
      context "when client presents correct auth token" do
        let!(:response) do
          agent.post!("http://localhost:#{port}/meh",
                      :headers => {
                        "content-type" => "text/plain",
                        "authorization" => "Basic #{auth_token}"
                      }, :body => "hi")
        end
        it "should respond with 200" do
          expect(response.status).to eq(200)
        end
        it "should generate an event" do
          expect(queue).to_not be_empty
        end
      end
    end

  end

  context "with :ssl => false" do
    subject { LogStash::Inputs::Http.new("port" => port, "ssl" => false) }
    it "should not raise exception" do
      expect { subject.register }.to_not raise_exception
    end
  end
  context "with :ssl => true" do
    context "without :keystore and :keystore_password" do
      subject { LogStash::Inputs::Http.new("port" => port, "ssl" => true) }
      it "should raise exception" do
        expect { subject.register }.to raise_exception(LogStash::ConfigurationError)
      end
    end
    context "with :keystore and :keystore_password" do
      let(:keystore) { Stud::Temporary.file }
      subject { LogStash::Inputs::Http.new("port" => port, "ssl" => true,
                                           "keystore" => keystore.path,
                                           "keystore_password" => "pass") }
      it "should not raise exception" do
        expect { subject.register }.to_not raise_exception
      end
    end
  end
end
