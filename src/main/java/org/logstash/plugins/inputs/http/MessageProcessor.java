package org.logstash.plugins.inputs.http;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.logstash.plugins.inputs.http.util.RejectableRunnable;

public class MessageProcessor implements RejectableRunnable {
    private final ChannelHandlerContext ctx;
    private final FullHttpRequest req;
    private final String remoteAddress;
    private final IMessageHandler messageHandler;

    public MessageProcessor(ChannelHandlerContext ctx, FullHttpRequest req, String remoteAddress,
                            IMessageHandler messageHandler) {
        this.ctx = ctx;
        this.req = req;
        this.remoteAddress = remoteAddress;
        this.messageHandler = messageHandler;
    }

    public void onRejection() {
        try {
            final DefaultHttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.TOO_MANY_REQUESTS);
            response.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0);
            ctx.writeAndFlush(response);
        } finally {
            req.release();
        }
    }

    @Override
    public void run() {
        try {
            final FullHttpResponse response = messageHandler.onNewMessage(remoteAddress, req);
            ctx.writeAndFlush(response);
        } finally {
            req.release();
        }
    }
}

