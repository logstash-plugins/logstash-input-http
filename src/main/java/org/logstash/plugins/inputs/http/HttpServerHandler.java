package org.logstash.plugins.inputs.http;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.compression.DecompressionException;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;

import java.net.InetSocketAddress;
import java.util.concurrent.ThreadPoolExecutor;

import static io.netty.buffer.Unpooled.copiedBuffer;

/**
 * Created by joaoduarte on 11/10/2017.
 */
public class HttpServerHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private final IMessageHandler messageHandler;
    private final ThreadPoolExecutor executorGroup;

    public HttpServerHandler(IMessageHandler messageHandler, ThreadPoolExecutor executorGroup) {
        this.messageHandler = messageHandler;
        this.executorGroup = executorGroup;
    }

    @Override
    public void channelRead0(ChannelHandlerContext ctx, FullHttpRequest msg) {
        final String remoteAddress = ((InetSocketAddress) ctx.channel().remoteAddress()).getAddress().getHostAddress();
        msg.retain();
        final MessageProcessor messageProcessor = new MessageProcessor(ctx, msg, remoteAddress, messageHandler);
        executorGroup.execute(messageProcessor);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        final ByteBuf content = copiedBuffer(cause.getMessage().getBytes());
        final HttpResponseStatus responseStatus;

        if (cause instanceof DecompressionException) {
            responseStatus = HttpResponseStatus.BAD_REQUEST;
        } else {
            responseStatus = HttpResponseStatus.INTERNAL_SERVER_ERROR;
        }
        final DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                responseStatus,
                content
        );
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain");
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
        ctx.writeAndFlush(response);
    }
}