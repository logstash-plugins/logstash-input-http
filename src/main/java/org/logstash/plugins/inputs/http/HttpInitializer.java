package org.logstash.plugins.inputs.http;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpContentDecompressor;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.ssl.SslHandler;
import org.logstash.plugins.inputs.http.util.SslHandlerProvider;

import java.util.concurrent.ThreadPoolExecutor;

/**
 * Created by joaoduarte on 11/10/2017.
 */
public class HttpInitializer extends ChannelInitializer<SocketChannel> {
    private final IMessageHandler messageHandler;
    private SslHandlerProvider sslHandlerProvider;
    private final int maxContentLength;
    private final ThreadPoolExecutor executorGroup;

    public HttpInitializer(IMessageHandler messageHandler, ThreadPoolExecutor executorGroup,
                           int maxContentLength) {
        this.messageHandler = messageHandler;
        this.executorGroup = executorGroup;
        this.maxContentLength = maxContentLength;
    }

    protected void initChannel(SocketChannel socketChannel) throws Exception {
        ChannelPipeline pipeline = socketChannel.pipeline();

        if(sslHandlerProvider != null) {
            SslHandler sslHandler = sslHandlerProvider.getSslHandler(socketChannel.alloc());
            pipeline.addLast(sslHandler);
        }
        pipeline.addLast(new HttpServerCodec());
        pipeline.addLast(new HttpContentDecompressor());
        pipeline.addLast(new HttpObjectAggregator(maxContentLength));
        pipeline.addLast(new HttpServerHandler(messageHandler.copy(), executorGroup));
    }

    public void enableSSL(SslHandlerProvider sslHandlerProvider) {
        this.sslHandlerProvider = sslHandlerProvider;
    }
}

