# encoding: utf-8
require "logstash-input-http_jars"
java_import org.logstash.plugins.inputs.http.MessageHandler
java_import "io.netty.handler.codec.http.DefaultFullHttpResponse"
java_import "io.netty.handler.codec.http.HttpHeaderNames"
java_import "io.netty.handler.codec.http.HttpVersion"
java_import "io.netty.handler.codec.http.HttpResponseStatus"
java_import "io.netty.buffer.Unpooled"
java_import "io.netty.util.CharsetUtil"

module LogStash module Inputs class Http
  class MessageHandler
    include org.logstash.plugins.inputs.http.IMessageHandler

    attr_reader :input

    def initialize(input, default_codec, additional_codecs)
      @input = input
      @default_codec = default_codec
      @additional_codecs = additional_codecs
    end

    def onNewMessage(remote_address, message)
      if valid_auth?(message)
        message.headers.remove(HttpHeaderNames::AUTHORIZATION)
        status, headers, content = @input.decode_body(remote_address, message, @default_codec, @additional_codecs)
      else
        status, headers, content = 401, {}, 'failed to authenticate'
      end
      generate_response(status, headers, content)
    end

    private
    def generate_response(status, headers, content)
      payload = Unpooled.copiedBuffer(content.to_java_string, CharsetUtil::UTF_8)
      response = DefaultFullHttpResponse.new(
        HttpVersion::HTTP_1_1,
        HttpResponseStatus.valueOf(status),
        payload)
      response.headers().set(HttpHeaderNames::CONTENT_LENGTH, payload.readable_bytes());
      response.headers().set(HttpHeaderNames::CONTENT_TYPE, "text/plain");
      headers.each { |k, v| response.headers().set(k, v) }
      response
    end

    def copy
      MessageHandler.new(@input, @default_codec.clone, clone_additional_codecs())
    end

    def clone_additional_codecs
      clone_additional_codecs = {}
      @additional_codecs.each do |content_type, codec|
        clone_additional_codecs[content_type] = codec.clone
      end
      clone_additional_codecs
    end

    def valid_auth?(message)
      @input.valid_auth?(message.headers.get(HttpHeaderNames::AUTHORIZATION))
    end
  end
end; end; end
