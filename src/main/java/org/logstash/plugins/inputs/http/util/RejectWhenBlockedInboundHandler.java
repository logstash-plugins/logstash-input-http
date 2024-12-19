package org.logstash.plugins.inputs.http.util;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.util.ReferenceCountUtil;

import java.time.Duration;

/**
 * A {@link RejectWhenBlockedInboundHandler} is a {@link io.netty.channel.ChannelInboundHandler} that rejects incoming
 * http requests with HTTP 429 when its {@link ExecutionObserver} reports that one or more active executions have been
 * running for more than a configurable {@link Duration}. It must be injected into a pipeline <em>after</em> the
 * {@link io.netty.handler.codec.http.HttpServerCodec} that decodes the incoming byte-stream into {@link HttpRequest}s.
 *
 * <p>
 *     This implementation is keep-alive friendly, but will close the connection if the current request didn't
 *     include an {@code Expect: 100-continue} to indicate that they won't pre-send the payload.
 * </p>
 */
public class RejectWhenBlockedInboundHandler extends ChannelInboundHandlerAdapter {

    private final ExecutionObserver executionObserver;
    private final FullHttpResponse REJECT_RESPONSE = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.TOO_MANY_REQUESTS, Unpooled.EMPTY_BUFFER);

    private final Duration blockThreshold;

    public RejectWhenBlockedInboundHandler(final ExecutionObserver executionObserver,
                                           final Duration blockThreshold) {
        this.executionObserver = executionObserver;
        this.blockThreshold = blockThreshold;
    }

    @Override
    public void channelRead(final ChannelHandlerContext ctx,
                            final Object msg) throws Exception {
        if (msg instanceof HttpRequest) {
            final HttpRequest req = (HttpRequest) msg;
            if (executionObserver.anyExecuting(this.blockThreshold)) {
                final HttpResponse rejection = REJECT_RESPONSE.retainedDuplicate();
                ReferenceCountUtil.release(msg);
                ChannelFuture channelFuture = ctx.writeAndFlush(rejection);

                // If the client started to send data already, close because it's impossible to recover.
                // If keep-alive is on and 'Expect: 100-continue' is present, it is safe to leave the connection open.
                if (HttpUtil.isKeepAlive(req) && HttpUtil.is100ContinueExpected(req)) {
                    channelFuture.addListener(ChannelFutureListener.CLOSE_ON_FAILURE);
                } else {
                    channelFuture.addListener(ChannelFutureListener.CLOSE);
                }

                return;
            }
        }
        super.channelRead(ctx, msg);
    }
}
