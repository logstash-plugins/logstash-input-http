package org.logstash.plugins.inputs.http.util;

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;

public class SslHandlerProvider {

    private final SslContext sslContext;
    private final int sslHandshakeTimeoutMillis;

    public SslHandlerProvider(SslContext context, int sslHandshakeTimeoutMillis){
        this.sslContext = context;
        this.sslHandshakeTimeoutMillis = sslHandshakeTimeoutMillis;
    }

    public SslHandler getSslHandler(ByteBufAllocator bufferAllocator) {
        SslHandler handler = sslContext.newHandler(bufferAllocator);
        handler.setHandshakeTimeoutMillis(sslHandshakeTimeoutMillis);
        return handler;
    }
}
