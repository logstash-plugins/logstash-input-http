# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "stud/interval"
require "logstash-input-http_jars"
require "logstash/plugin_mixins/ecs_compatibility_support"
require "logstash/plugin_mixins/normalize_config_support"

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
  include LogStash::PluginMixins::ECSCompatibilitySupport(:disabled, :v1, :v8 => :v1)

  include LogStash::PluginMixins::NormalizeConfigSupport

  require "logstash/inputs/http/tls"

  java_import "io.netty.handler.codec.http.HttpUtil"
  java_import 'org.logstash.plugins.inputs.http.util.SslSimpleBuilder'

  config_name "http"

  # Codec used to decode the incoming data.
  # This codec will be used as a fall-back if the content-type
  # is not found in the "additional_codecs" hash
  default :codec, "plain"

  # The host or ip to bind
  config :host, :validate => :string, :default => "0.0.0.0"

  # The TCP port to bind to
  config :port, :validate => :number, :default => 8080

  # Username for basic authorization
  config :user, :validate => :string, :required => false

  # Password for basic authorization
  config :password, :validate => :password, :required => false

  # Events are by default sent in plain text. You can
  # enable encryption by setting `ssl` to true and configuring
  # the `ssl_certificate` and `ssl_key` options.
  config :ssl, :validate => :boolean, :default => false, :deprecated => "Set 'ssl_enabled' instead."

  # Events are by default sent in plain text. You can
  # enable encryption by setting `ssl` to true and configuring
  # the `ssl_certificate` and `ssl_key` options.
  config :ssl_enabled, :validate => :boolean, :default => false

  # SSL certificate to use.
  config :ssl_certificate, :validate => :path

  # SSL key to use.
  # NOTE: This key need to be in the PKCS8 format, you can convert it with https://www.openssl.org/docs/man1.1.0/apps/pkcs8.html[OpenSSL]
  # for more information.
  config :ssl_key, :validate => :path

  # The JKS keystore password
  config :ssl_keystore_password, :validate => :password

  # The JKS keystore to validate the client's certificates
  config :ssl_keystore_path, :validate => :path

  # SSL key passphrase to use.
  config :ssl_key_passphrase, :validate => :password

  # Validate client certificates against these authorities.
  # You can define multiple files or paths. All the certificates will
  # be read and added to the trust store. You need to configure the `ssl_client_authentication`
  # to `optional` or `required` to enable the verification.
  config :ssl_certificate_authorities, :validate => :array, :default => []

  # Controls the server’s behavior in regard to requesting a certificate from client connections.
  # `none`: No client authentication
  # `optional`: Requests a client certificate but the client is not required to present one.
  # `required`: Forces a client to present a certificate.
  #
  # This option needs to be used with `ssl_certificate_authorities` and a defined list of CAs.
  config :ssl_client_authentication, :validate => %w[none optional required], :default => 'none'

  # By default the server doesn't do any client verification.
  #
  # `peer` will make the server ask the client to provide a certificate.
  # If the client provides a certificate, it will be validated.
  #
  # `force_peer` will make the server ask the client to provide a certificate.
  # If the client doesn't provide a certificate, the connection will be closed.
  #
  # This option needs to be used with `ssl_certificate_authorities` and a defined list of CAs.
  config :ssl_verify_mode, :validate => ["none", "peer", "force_peer"], :default => "none", :deprecated => "Set 'ssl_client_authentication' instead."

  # Time in milliseconds for an incomplete ssl handshake to timeout
  config :ssl_handshake_timeout, :validate => :number, :default => 10000

  # The list of ciphers suite to use, listed by priorities.
  config :ssl_cipher_suites, :validate => SslSimpleBuilder::SUPPORTED_CIPHERS.to_a,
                             :default => SslSimpleBuilder.getDefaultCiphers, :list => true

  config :ssl_supported_protocols, :validate => ['TLSv1.1', 'TLSv1.2', 'TLSv1.3'], :default => ['TLSv1.2', 'TLSv1.3'], :list => true

  # Apply specific codecs for specific content types.
  # The default codec will be applied only after this list is checked
  # and no codec for the request's content-type is found
  config :additional_codecs, :validate => :hash, :default => { "application/json" => "json" }

  # specify a custom set of response headers
  config :response_headers, :validate => :hash, :default => { 'Content-Type' => 'text/plain' }

  # target field for the client host of the http request
  config :remote_host_target_field, :validate => :string

  # target field for the client host of the http request
  config :request_headers_target_field, :validate => :string

  config :threads, :validate => :number, :required => false, :default => ::LogStash::Config::CpuCoreStrategy.maximum

  config :max_pending_requests, :validate => :number, :required => false, :default => 200

  config :max_content_length, :validate => :number, :required => false, :default => 100 * 1024 * 1024

  config :response_code, :validate => [200, 201, 202, 204], :default => 200

  # Deprecated options

  # The JKS keystore to validate the client's certificates
  config :keystore, :validate => :path, :deprecated => "Set 'ssl_keystore_path' instead."

  # The JKS keystore password
  config :keystore_password, :validate => :password, :deprecated => "Set 'ssl_keystore_password' instead."

  config :verify_mode, :validate => ['none', 'peer', 'force_peer'], :default => 'none', :deprecated => "Set 'ssl_client_authentication' instead."

  config :cipher_suites, :validate => :array, :default => [], :deprecated => "Set 'ssl_cipher_suites' instead."

  # The minimum TLS version allowed for the encrypted connections. The value must be one of the following:
  # 1.0 for TLS 1.0, 1.1 for TLS 1.1, 1.2 for TLS 1.2, 1.3 for TLS 1.3
  config :tls_min_version, :validate => :number, :default => TLS.min.version, :deprecated => "Set 'ssl_supported_protocols' instead."

  # The maximum TLS version allowed for the encrypted connections. The value must be the one of the following:
  # 1.0 for TLS 1.0, 1.1 for TLS 1.1, 1.2 for TLS 1.2, 1.3 for TLS 1.3
  config :tls_max_version, :validate => :number, :default => TLS.max.version, :deprecated => "Set 'ssl_supported_protocols' instead."

  attr_reader :codecs

  NON_PREFIXED_SSL_CONFIGS = Set[
    'keystore',
    'keystore_password',
    'verify_mode',
    'tls_min_version',
    'tls_max_version',
    'cipher_suites',
  ].freeze

  SSL_CLIENT_AUTH_NONE = 'none'.freeze
  SSL_CLIENT_AUTH_OPTIONAL = 'optional'.freeze
  SSL_CLIENT_AUTH_REQUIRED = 'required'.freeze

  SSL_VERIFY_MODE_TO_CLIENT_AUTHENTICATION_MAP = {
    'none' => SSL_CLIENT_AUTH_NONE,
    'peer' => SSL_CLIENT_AUTH_OPTIONAL,
    'force_peer' => SSL_CLIENT_AUTH_REQUIRED
  }.freeze

  private_constant :SSL_CLIENT_AUTH_NONE
  private_constant :SSL_CLIENT_AUTH_OPTIONAL
  private_constant :SSL_CLIENT_AUTH_REQUIRED
  private_constant :NON_PREFIXED_SSL_CONFIGS
  private_constant :SSL_VERIFY_MODE_TO_CLIENT_AUTHENTICATION_MAP

  public
  def register

    setup_ssl_params!

    validate_ssl_settings!

    if @user && @password
      token = Base64.strict_encode64("#{@user}:#{@password.value}")
      @auth_token = "Basic #{token}"
    end

    @codecs = Hash.new

    @additional_codecs.each do |content_type, codec|
      @codecs[content_type] = initialize_codec(codec)
    end

    require "logstash/inputs/http/message_handler"
    message_handler = MessageHandler.new(self, @codec, @codecs, @auth_token)
    @http_server = create_http_server(message_handler)

    @remote_host_target_field ||= ecs_select[disabled: "host", v1: "[host][ip]"]
    @request_headers_target_field ||= ecs_select[disabled: "headers", v1: "[@metadata][input][http][request][headers]"]
  end # def register

  def run(queue)
    @queue = queue
    @logger.info("Starting http input listener", :address => "#{@host}:#{@port}", :ssl => "#{@ssl}")
    @http_server.run()
  end

  def stop
    @http_server.close() rescue nil
  end

  def close
    @http_server.close() rescue nil
  end

  def decode_body(headers, remote_address, body, default_codec, additional_codecs)
    content_type = headers.fetch("content_type", "")
    codec = additional_codecs.fetch(HttpUtil.getMimeType(content_type), default_codec)
    codec.decode(body) { |event| push_decoded_event(headers, remote_address, event) }
    codec.flush { |event| push_decoded_event(headers, remote_address, event) }
    true
  rescue => e
    @logger.error(
      "unable to process event.",
      :message => e.message,
      :class => e.class.name,
      :backtrace => e.backtrace
    )
    false
  end

  def push_decoded_event(headers, remote_address, event)
    add_ecs_fields(headers, event)
    event.set(@request_headers_target_field, headers)
    event.set(@remote_host_target_field, remote_address)
    decorate(event)
    @queue << event
  end

  def add_ecs_fields(headers, event)
    return if ecs_compatibility == :disabled

    http_version = headers.get("http_version")
    event.set("[http][version]", http_version) if http_version

    http_user_agent = headers.get("http_user_agent")
    event.set("[user_agent][original]", http_user_agent) if http_user_agent

    http_host = headers.get("http_host")
    domain, port = self.class.get_domain_port(http_host)
    event.set("[url][domain]", domain) if domain
    event.set("[url][port]", port) if port

    request_method = headers.get("request_method")
    event.set("[http][method]", request_method) if request_method

    request_path = headers.get("request_path")
    event.set("[url][path]", request_path) if request_path

    content_length = headers.get("content_length")
    event.set("[http][request][body][bytes]", content_length) if content_length

    content_type = headers.get("content_type")
    event.set("[http][request][mime_type]", content_type) if content_type
  end

  # match the domain and port in either IPV4, "127.0.0.1:8080", or IPV6, "[2001:db8::8a2e:370:7334]:8080", style
  # return [domain, port]
  def self.get_domain_port(http_host)
    if /^(([^:]+)|\[(.*)\])\:([\d]+)$/ =~ http_host
      ["#{$2 || $3}", $4.to_i]
    else
      [http_host, nil]
    end
  end

  def validate_ssl_settings!
    ssl_config_name = original_params.include?('ssl') ? 'ssl' : 'ssl_enabled'

    unless @ssl_enabled
      ignored_ssl_settings = original_params.select { |k| k != 'ssl_enabled' && k.start_with?('ssl_') || NON_PREFIXED_SSL_CONFIGS.include?(k) }
      @logger.warn("Configured SSL settings are not used when `#{ssl_config_name}` is set to `false`: #{ignored_ssl_settings.keys}") if ignored_ssl_settings.any?
      return # code bellow assumes `ssl_enabled => true`
    end

    if @ssl_certificate && !@ssl_key
      raise LogStash::ConfigurationError, "Using an `ssl_certificate` requires an `ssl_key`"
    elsif @ssl_key && !@ssl_certificate
      raise LogStash::ConfigurationError, 'An `ssl_certificate` is required when using an `ssl_key`'
    end

    unless ssl_key_configured? || ssl_jks_configured?
      raise LogStash::ConfigurationError, "Either an `ssl_certificate` or `ssl_keystore_path` is required when SSL is enabled `#{ssl_config_name} => true`"
    end

    if require_certificate_authorities? && !certificate_authorities_configured?
      config_name, optional, required = provided_client_authentication_config([SSL_CLIENT_AUTH_OPTIONAL, SSL_CLIENT_AUTH_REQUIRED])
      raise LogStash::ConfigurationError, "Using `#{config_name}` set to `#{optional}` or `#{required}`, requires the configuration of `ssl_certificate_authorities`"
    end

    if !require_certificate_authorities? && certificate_authorities_configured?
      config_name, optional, required = provided_client_authentication_config([SSL_CLIENT_AUTH_OPTIONAL, SSL_CLIENT_AUTH_REQUIRED])
      raise LogStash::ConfigurationError, "The configuration of `ssl_certificate_authorities` requires setting `#{config_name}` to `#{optional}` or '#{required}'"
    end
  end

  def setup_ssl_params!
    @ssl_enabled = normalize_config(:ssl_enabled) do |normalizer|
      normalizer.with_deprecated_alias(:ssl)
    end

    @ssl_cipher_suites = normalize_config(:ssl_cipher_suites) do |normalizer|
      normalizer.with_deprecated_alias(:cipher_suites)
    end

    @ssl_supported_protocols = normalize_config(:ssl_supported_protocols) do |normalizer|
      normalizer.with_deprecated_mapping(:tls_min_version, :tls_max_version) do |tls_min_version, tls_max_version|
        TLS.get_supported(tls_min_version..tls_max_version).map(&:name)
      end
    end

    @ssl_client_authentication = normalize_config(:ssl_client_authentication) do |normalizer|
      normalizer.with_deprecated_mapping(:verify_mode, :ssl_verify_mode) do |verify_mode, ssl_verify_mode|
        normalize_ssl_client_authentication_value!(verify_mode, ssl_verify_mode)
      end
    end

    @ssl_keystore_path = normalize_config(:ssl_keystore_path) do |normalizer|
      normalizer.with_deprecated_alias(:keystore)
    end

    @ssl_keystore_password = normalize_config(:ssl_keystore_password) do |normalizer|
      normalizer.with_deprecated_alias(:keystore_password)
    end

    params['ssl_enabled'] = @ssl_enabled unless @ssl_enabled.nil?
    params['ssl_cipher_suites'] = @ssl_cipher_suites unless @ssl_cipher_suites.nil?
    params['ssl_supported_protocols'] = @ssl_supported_protocols unless @ssl_supported_protocols.nil?
    params['ssl_client_authentication'] = @ssl_client_authentication unless @ssl_client_authentication.nil?
    params['ssl_keystore_path'] = @ssl_keystore_path unless @ssl_keystore_path.nil?
    params['ssl_keystore_password'] = @ssl_keystore_password unless @ssl_keystore_password.nil?
  end

  def normalize_ssl_client_authentication_value!(verify_mode, ssl_verify_mode)
    verify_mode_explicitly_set = original_params.key?("verify_mode")

    if verify_mode_explicitly_set && original_params.key?("ssl_verify_mode")
      raise LogStash::ConfigurationError, "Both (deprecated) `ssl_verify_mode` and `verify_mode` were set. Use only `ssl_verify_mode`"
    end

    deprecated_value = (verify_mode_explicitly_set ? verify_mode : ssl_verify_mode).downcase
    SSL_VERIFY_MODE_TO_CLIENT_AUTHENTICATION_MAP[deprecated_value]
  end

  def create_http_server(message_handler)
    org.logstash.plugins.inputs.http.NettyHttpServer.new(
      @host, @port, message_handler, build_ssl_params, @threads, @max_pending_requests, @max_content_length, @response_code)
  end

  def build_ssl_params
    return nil unless @ssl_enabled

    if @ssl_keystore_path && @ssl_keystore_password
      ssl_builder = org.logstash.plugins.inputs.http.util.JksSslBuilder.new(@ssl_keystore_path, @ssl_keystore_password.value)
    else
      ssl_builder = new_ssl_simple_builder
    end

    new_ssl_handshake_provider(ssl_builder)
  end

  def new_ssl_simple_builder
    passphrase = @ssl_key_passphrase.nil? ? nil : @ssl_key_passphrase.value
    begin
      ssl_context_builder = SslSimpleBuilder.new(@ssl_certificate, @ssl_key, passphrase)
                            .setProtocols(@ssl_supported_protocols)
                            .setCipherSuites(normalized_cipher_suites)

      if client_authentication_enabled?
        ssl_context_builder.setClientAuthentication(ssl_simple_builder_verify_mode, @ssl_certificate_authorities)
      end

      ssl_context_builder
    rescue java.lang.IllegalArgumentException => e
      @logger.error("SSL configuration invalid", error_details(e))
      raise LogStash::ConfigurationError, e
    end
  end

  def ssl_simple_builder_verify_mode
    return SslSimpleBuilder::SslClientVerifyMode::OPTIONAL if client_authentication_optional?
    return SslSimpleBuilder::SslClientVerifyMode::REQUIRED if client_authentication_required?
    return SslSimpleBuilder::SslClientVerifyMode::NONE if client_authentication_none?
    raise LogStash::ConfigurationError, "Invalid `ssl_client_authentication` value #{@ssl_client_authentication}"
  end

  def ssl_key_configured?
    !!(@ssl_certificate && @ssl_key)
  end

  def ssl_jks_configured?
    !!(@ssl_keystore_path && @ssl_keystore_password)
  end

  def client_authentication_enabled?
    client_authentication_optional? || client_authentication_required?
  end

  def require_certificate_authorities?
    client_authentication_required? || client_authentication_optional?
  end

  def certificate_authorities_configured?
    @ssl_certificate_authorities && @ssl_certificate_authorities.size > 0
  end

  def client_authentication_required?
    @ssl_client_authentication && @ssl_client_authentication.downcase == SSL_CLIENT_AUTH_REQUIRED
  end

  def client_authentication_none?
    @ssl_client_authentication && @ssl_client_authentication.downcase == SSL_CLIENT_AUTH_NONE
  end

  def client_authentication_optional?
    @ssl_client_authentication && @ssl_client_authentication.downcase == SSL_CLIENT_AUTH_OPTIONAL
  end

  def provided_client_authentication_config(values = [@ssl_client_authentication])
    if original_params.include?('ssl_verify_mode')
      ['ssl_verify_mode', *values.map { |v| SSL_VERIFY_MODE_TO_CLIENT_AUTHENTICATION_MAP.key(v) }]
    elsif original_params.include?('verify_mode')
      ['verify_mode', *values.map { |v| SSL_VERIFY_MODE_TO_CLIENT_AUTHENTICATION_MAP.key(v) }]
    else
      ['ssl_client_authentication', *values]
    end
  end

  private

  def normalized_cipher_suites
    @ssl_cipher_suites.map(&:upcase)
  end

  def new_ssl_handshake_provider(ssl_builder)
    begin
      org.logstash.plugins.inputs.http.util.SslHandlerProvider.new(ssl_builder.build(), @ssl_handshake_timeout)
    rescue java.lang.IllegalArgumentException => e
      @logger.error("SSL configuration invalid", error_details(e))
      raise LogStash::ConfigurationError, e
    rescue java.lang.Exception => e
      @logger.error("SSL configuration failed", error_details(e, true))
      raise e
    end
  end

  def error_details(e, trace = false)
    error_details = { :exception => e.class, :message => e.message }
    error_details[:backtrace] = e.backtrace if trace || @logger.debug?
    cause = e.cause
    if cause && e != cause
      error_details[:cause] = { :exception => cause.class, :message => cause.message }
      error_details[:cause][:backtrace] = cause.backtrace if trace || @logger.debug?
    end
    error_details
  end

  def initialize_codec(codec_name)
    codec_klass = LogStash::Plugin.lookup("codec", codec_name)
    if defined?(::LogStash::Plugins::Contextualizer)
      ::LogStash::Plugins::Contextualizer.initialize_plugin(execution_context, codec_klass)
    else
      codec_klass.new 
    end
  end

end # class LogStash::Inputs::Http
