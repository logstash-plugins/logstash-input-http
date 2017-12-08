# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "stud/interval"
require "socket" # for Socket.gethostname
require "puma/server"
require "puma/minissl"
require "base64"
require "rack"
require "java"

##
# We keep the redefined method in a new http server class, this is because
# in other parts of logstash we might be using puma as webserver, for example
# in the sinatra part we need this method to actually return the REQUEST_PATH, 
# so it can actually infer the right resource to use.
# Fixes https://github.com/logstash-plugins/logstash-input-http/issues/51
##
class HTTPInputWebServer < Puma::Server
  # ensure this method doesn't mess up our vanilla request
  def normalize_env(env, client); end
end

# Using this input you can receive single or multiline events over http(s).
# Applications can send a HTTP POST request with a body to the endpoint started by this
# input and Logstash will convert it into an event for subsequent processing. Users 
# can pass plain text, JSON, or any formatted data and use a corresponding codec with this
# input. For Content-Type `application/json` the `json` codec is used, but for all other
# data formats, `plain` codec is used.
#
# This input can also be used to receive webhook requests to integrate with other services
# and applications. By taking advantage of the vast plugin ecosystem available in Logstash
# you can trigger actionable events right from your application.
# 
# ==== Security
# This plugin supports standard HTTP basic authentication headers to identify the requester.
# You can pass in an username, password combination while sending data to this input
#
# You can also setup SSL and send data securely over https, with an option of validating 
# the client's certificate. Currently, the certificate setup is through 
# https://docs.oracle.com/cd/E19509-01/820-3503/ggfen/index.html[Java Keystore 
# format]
#
class LogStash::Inputs::Http < LogStash::Inputs::Base
  #TODO: config :cacert, :validate => :path

  config_name "http"

  # Codec used to decode the incoming data.
  # This codec will be used as a fall-back if the content-type
  # is not found in the "additional_codecs" hash
  default :codec, "plain"

  # The host or ip to bind
  config :host, :validate => :string, :default => "0.0.0.0"

  # The TCP port to bind to
  config :port, :validate => :number, :default => 8080

  # Maximum number of threads to use
  config :threads, :validate => :number, :default => 4

  # Username for basic authorization
  config :user, :validate => :string, :required => false

  # Password for basic authorization
  config :password, :validate => :password, :required => false

  # SSL Configurations
  #
  # Enable SSL
  config :ssl, :validate => :boolean, :default => false

  # The JKS keystore to validate the client's certificates
  config :keystore, :validate => :path

  # Set the truststore password
  config :keystore_password, :validate => :password

  # Set the client certificate verification method. Valid methods: none, peer, force_peer
  config :verify_mode, :validate => ['none', 'peer', 'force_peer'], :default => 'none'

  # Apply specific codecs for specific content types.
  # The default codec will be applied only after this list is checked
  # and no codec for the request's content-type is found
  config :additional_codecs, :validate => :hash, :default => { "application/json" => "json" }

  # specify a custom set of response headers
  config :response_headers, :validate => :hash, :default => { 'Content-Type' => 'text/plain' }

  # useless headers puma adds to the requests
  # mostly due to rack compliance
  REJECTED_HEADERS = ["puma.socket", "rack.hijack?", "rack.hijack", "rack.url_scheme", "rack.after_reply", "rack.version", "rack.errors", "rack.multithread", "rack.multiprocess", "rack.run_once", "SCRIPT_NAME", "QUERY_STRING", "SERVER_PROTOCOL", "SERVER_SOFTWARE", "GATEWAY_INTERFACE"]

  public
  def register
    require "logstash/util/http_compressed_requests"
    @server = ::HTTPInputWebServer.new(nil) # we'll set the rack handler later
    if @user && @password then
      token = Base64.strict_encode64("#{@user}:#{@password.value}")
      @auth_token = "Basic #{token}"
    end
    if @ssl
      if @keystore.nil? || @keystore_password.nil?
        raise(LogStash::ConfigurationError, "Settings :keystore and :keystore_password are required because :ssl is enabled.")
      end
      ctx = Puma::MiniSSL::Context.new
      ctx.keystore = @keystore
      ctx.keystore_pass = @keystore_password.value
      ctx.verify_mode = case @verify_mode
                        when 'peer'
                          Puma::MiniSSL::VERIFY_PEER
                        when 'force_peer'
                          Puma::MiniSSL::VERIFY_PEER | Puma::MiniSSL::VERIFY_FAIL_IF_NO_PEER_CERT
                        when 'none'
                          Puma::MiniSSL::VERIFY_NONE
                        end
      @server.add_ssl_listener(@host, @port, ctx)
    else
      @server.add_tcp_listener(@host, @port)
    end
    @server.min_threads = 0
    # The actual number of threads is one higher to let us reject additional requests
    @server.max_threads = @threads + 1
    @codecs = Hash.new

    @additional_codecs.each do |content_type, codec|
      @codecs[content_type] = LogStash::Plugin.lookup("codec", codec).new
    end

    @write_slots = java.util.concurrent.ArrayBlockingQueue.new(threads)
    threads.times do
      # Freeze these guys just in case, since they aren't threadsafe
      @write_slots.put(Hash[@codecs.map {|k,v| [k.freeze, v.clone].freeze }.freeze].freeze)
    end

  end # def register

  BUSY_RESPONSE = ['Server busy, please retry request later'.freeze].freeze
  def run(queue)
    # proc needs to be defined at this context
    # to capture @codecs, @logger and lowercase_keys
    p = Proc.new do |req|
      begin
        remote_host = req['puma.socket'].peeraddr[3]
        REJECTED_HEADERS.each {|k| req.delete(k) }
        req = lowercase_keys(req)
        body = req.delete("rack.input")
        local_codecs = @write_slots.poll()
        if !local_codecs # No free write slot
          next [429, {}, BUSY_RESPONSE]
        end
        begin
          codec = local_codecs.fetch(req["content_type"], @codec)
          codec.decode(body.read) do |event|
            event.set("host", remote_host)
            event.set("headers", req)
            decorate(event)
            queue << event
          end
        ensure
          @write_slots.put(local_codecs)
        end
        ['200', @response_headers, ['ok']]
      rescue => e
        @logger.error(
          "unable to process event.", 
          :request => req,
          :message => e.message,
          :class => e.class.name,
          :backtrace => e.backtrace
        )
        ['500', @response_headers, ['internal error']]
      end
    end

    auth = Proc.new do |username, password|
      username == @user && password == @password.value
    end if (@user && @password)

    @server.app = Rack::Builder.new do
      use(Rack::Auth::Basic, &auth) if auth
      use CompressedRequests
      run(p)
    end
    @server.run.join
  end

  private
  def lowercase_keys(hash)
    new_hash = {}
    hash.each_pair do |k,v|
      new_hash[k.downcase] = v
    end
    new_hash
  end

  public
  def stop
    return unless @server
    @server.stop(true)
    @server.binder.close if @server.binder
  rescue IOError
    # do nothing
  end

end # class LogStash::Inputs::Http
