package org.logstash.plugins.inputs.http;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.logstash.plugins.inputs.http.util.CustomRejectedExecutionHandler;
import org.logstash.plugins.inputs.http.util.SslHandlerProvider;

import java.io.Closeable;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.logstash.plugins.inputs.http.util.DaemonThreadFactory.daemonThreadFactory;

/**
 * Created by joaoduarte on 11/10/2017.
 */
public class NettyHttpServer implements Runnable, Closeable {
    private final ServerBootstrap serverBootstrap;
    private final String host;
    private final int port;
    private final int connectionBacklog = 128;

    private final EventLoopGroup processorGroup;
    private final ThreadPoolExecutor executorGroup;
    private final HttpResponseStatus responseStatus;

    public NettyHttpServer(String host, int port, IMessageHandler messageHandler,
                           SslHandlerProvider sslHandlerProvider, int threads,
                           int maxPendingRequests, int maxContentLength, int responseCode)
    {
        this.host = host;
        this.port = port;
        this.responseStatus = HttpResponseStatus.valueOf(responseCode);
        processorGroup = new NioEventLoopGroup(threads, daemonThreadFactory("http-input-processor"));

        executorGroup = new ThreadPoolExecutor(threads, threads, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(maxPendingRequests), daemonThreadFactory("http-input-handler-executor"),
                new CustomRejectedExecutionHandler());

        final HttpInitializer httpInitializer = new HttpInitializer(messageHandler, executorGroup,
                                                                      maxContentLength, responseStatus);

        if (sslHandlerProvider != null) {
            httpInitializer.enableSSL(sslHandlerProvider);
        }

        serverBootstrap = new ServerBootstrap()
                .group(processorGroup)
                .channel(NioServerSocketChannel.class)
                .option(ChannelOption.SO_BACKLOG, connectionBacklog)
                .childOption(ChannelOption.SO_KEEPALIVE, true)
                .childHandler(httpInitializer);
    }

    @Override
    public void run() {
        try {
            executorGroup.prestartAllCoreThreads();
            final ChannelFuture channel = serverBootstrap.bind(host, port);
            channel.sync().channel().closeFuture().sync();
        } catch (final InterruptedException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Override
    public void close() {
        try {
            // stop accepting new connections first
            processorGroup.shutdownGracefully(0, 10, TimeUnit.SECONDS).sync();
            // then shutdown the message handler executor
            executorGroup.shutdown();
            try {
                if(!executorGroup.awaitTermination(5, TimeUnit.SECONDS)){
                    executorGroup.shutdownNow();
                }
            } catch (InterruptedException e) {
                throw new IllegalStateException("Arrived at illegal state during thread pool shutdown {}", e);
            }
            executorGroup.shutdownNow();
        } catch (final InterruptedException ex) {
            throw new IllegalStateException(ex);
        }
    }

}
