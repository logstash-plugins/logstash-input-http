require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/http"
require "json"
require "ftw"

describe LogStash::Inputs::Http do

  let(:agent) { FTW::Agent.new }
  let(:queue) { Queue.new }

  after :each do
    subject.teardown
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
      subject { LogStash::Inputs::Http.new("ssl" => true,
                                           "keystore" => "/tmp/keystore.jks",
                                           "keystore_password" => "pass") }
      it "should not raise exception" do
        expect { subject.register }.to_not raise_exception
      end
    end
  end
end
