require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/http"
require "json"
require "ftw"

describe LogStash::Inputs::Http do

  let(:agent) { FTW::Agent.new }

  it "should read events with json codec" do
    conf = <<-CONFIG
      input {
        http { codec => json }
      }
    CONFIG

    event = input(conf) do |pipeline, queue|
      agent.post!("http://127.0.0.1:8080/meh.json", :body => { "message" => "Hello" }.to_json)
      queue.pop
    end

    insist { event["message"] } == "Hello"
  end
end
