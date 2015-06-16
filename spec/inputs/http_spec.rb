require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/http"
require "json"
require "ftw"
require "stud/temporary"

describe LogStash::Inputs::Http do

  let(:agent) { FTW::Agent.new }
  let(:queue) { Queue.new }

  after :each do
    subject.teardown
  end

  context "with default codec" do
    subject { LogStash::Inputs::Http.new }
    context "when receiving a text/plain request" do
      it "should process the request normally" do
        subject.register
        Thread.new { subject.run(queue) }
        agent.post!("http://localhost:8080/meh.json",
                    :headers => { "content-type" => "text/plain" },
                    :body => "hello")
        event = queue.pop
        expect(event["message"]).to eq("hello")
      end
    end
    context "when receiving an application/json request" do
      it "should parse the json body" do
        subject.register
        Thread.new { subject.run(queue) }
        agent.post!("http://localhost:8080/meh.json",
                    :headers => { "content-type" => "application/json" },
                    :body => { "message_body" => "Hello" }.to_json)
        event = queue.pop
        expect(event["message_body"]).to eq("Hello")
      end
    end
  end

  context "with json codec" do
    subject { LogStash::Inputs::Http.new("codec" => "json") }
    it "should parse the json body" do
      subject.register
      Thread.new { subject.run(queue) }
      agent.post!("http://localhost:8080/meh.json", :body => { "message" => "Hello" }.to_json)
      event = queue.pop
      expect(event["message"]).to eq("Hello")
    end
  end

  context "when using a custom codec mapping" do
    subject { LogStash::Inputs::Http.new("additional_codecs" => { "application/json" => "plain" }) }
    it "should decode the message accordingly" do
      body = { "message" => "Hello" }.to_json
      subject.register
      Thread.new { subject.run(queue) }
      agent.post!("http://localhost:8080/meh.json",
                  :headers => { "content-type" => "application/json" },
                  :body => body)
      event = queue.pop
      expect(event["message"]).to eq(body)
    end
  end

  context "with :ssl => false" do
    subject { LogStash::Inputs::Http.new("ssl" => false) }
    it "should not raise exception" do
      expect { subject.register }.to_not raise_exception
    end
  end
  context "with :ssl => true" do
    context "without :keystore and :keystore_password" do
      subject { LogStash::Inputs::Http.new("ssl" => true) }
      it "should raise exception" do
        expect { subject.register }.to raise_exception(LogStash::ConfigurationError)
      end
    end
    context "with :keystore and :keystore_password" do
      let(:keystore) { Stud::Temporary.file }
      subject { LogStash::Inputs::Http.new("ssl" => true,
                                           "keystore" => keystore.path,
                                           "keystore_password" => "pass") }
      it "should not raise exception" do
        expect { subject.register }.to_not raise_exception
      end
    end
  end
end
