package org.logstash.plugins.inputs.http;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
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

    private final EventLoopGroup bossGroup;
    private final EventLoopGroup processorGroup;
    private final ThreadPoolExecutor executorGroup;
    private final HttpResponseStatus responseStatus;

    private volatile Channel serverChannel;

    public NettyHttpServer(final String id, final String host, final int port, final IMessageHandler messageHandler,
                           final SslHandlerProvider sslHandlerProvider, final int threads,
                           final int maxPendingRequests, final int maxContentLength, final int responseCode)
    {
        this.host = host;
        this.port = port;
        this.responseStatus = HttpResponseStatus.valueOf(responseCode);

        // boss group is responsible for accepting incoming connections and sending to worker loop
        // process group is channel handler, see the https://github.com/netty/netty/discussions/13305
        // see the https://github.com/netty/netty/discussions/11808#discussioncomment-1610918 for why separation is good
        bossGroup = new NioEventLoopGroup(1, daemonThreadFactory(id + "-bossGroup"));
        processorGroup = new NioEventLoopGroup(threads, daemonThreadFactory(id + "-processorGroup"));

        // event handler group
        executorGroup = new ThreadPoolExecutor(threads, threads, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(maxPendingRequests), daemonThreadFactory(id + "-executorGroup"),
                new CustomRejectedExecutionHandler());

        final HttpInitializer httpInitializer = new HttpInitializer(messageHandler, executorGroup,
                                                                      maxContentLength, responseStatus);

        if (sslHandlerProvider != null) {
            httpInitializer.enableSSL(sslHandlerProvider);
        }

        this.serverBootstrap = new ServerBootstrap()
                .group(bossGroup, processorGroup)
                .channel(NioServerSocketChannel.class)
                .option(ChannelOption.AUTO_READ, false) // delay accepting connections until we have a queue
                .option(ChannelOption.SO_BACKLOG, connectionBacklog)
                .childOption(ChannelOption.SO_KEEPALIVE, true)
                .childHandler(httpInitializer);
    }

    public synchronized void bind() {
        if (serverChannel != null && serverChannel.isOpen()) {
            throw new IllegalStateException("Server is already bound");
        }
        serverChannel = serverBootstrap.bind(host, port).syncUninterruptibly().channel();
    }

    @Override
    public void run() {
        synchronized(this) {
            if (serverChannel == null) {
                bind();
            }
        }
        try {
            executorGroup.prestartAllCoreThreads();
            serverChannel.config().setAutoRead(true); // begin accepting connections
            serverChannel.closeFuture().sync();
        } catch (final InterruptedException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Override
    public void close() {
        try {
            // stop accepting new connections first
            synchronized (this) {
                if (serverChannel != null && serverChannel.isOpen()) {
                    serverChannel.close().sync();
                }
            }
            bossGroup.shutdownGracefully().sync();
            // stop the worker group
            processorGroup.shutdownGracefully().sync();
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
