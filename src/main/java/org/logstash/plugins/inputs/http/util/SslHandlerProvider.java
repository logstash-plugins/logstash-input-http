package org.logstash.plugins.inputs.http.util;

import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import java.net.InetSocketAddress;
import java.util.Arrays;

public class SslHandlerProvider {

    private final static Logger logger = LogManager.getLogger(SslSimpleBuilder.class);
    private final SslContext sslContext;
    private SslClientVerifyMode verifyMode = SslClientVerifyMode.NONE;
    private long handshakeTimeoutMilliseconds = 10000;

    enum SslClientVerifyMode {
        VERIFY_PEER,
        FORCE_PEER,
        NONE
    }

    private String[] protocols = new String[] { "TLSv1.2", "TLSv1.3" };

    public SslHandlerProvider(SslContext sslContext) {
        this.sslContext = sslContext;
    }

    public SslHandler getSslHandler(final SocketChannel socketChannel) {
        final InetSocketAddress remoteAddress = socketChannel.remoteAddress();
        final String peerHost = remoteAddress.getHostString();
        final int peerPort = remoteAddress.getPort();
        final SslHandler sslHandler = sslContext.newHandler(socketChannel.alloc(), peerHost, peerPort);

        final SSLEngine engine = sslHandler.engine();
        engine.setEnabledProtocols(protocols);
        engine.setUseClientMode(false);

        final SSLParameters sslParameters = engine.getSSLParameters();
        sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
        engine.setSSLParameters(sslParameters);

        if (verifyMode == SslClientVerifyMode.FORCE_PEER) {
            // Explicitly require a client certificate
            engine.setNeedClientAuth(true);
        } else if (verifyMode == SslClientVerifyMode.VERIFY_PEER) {
            // If the client supply a client certificate we will verify it.
            engine.setWantClientAuth(true);
        }

        sslHandler.setHandshakeTimeoutMillis(handshakeTimeoutMilliseconds);

        return sslHandler;
    }

    public void setVerifyMode(String verifyMode) {
        if (verifyMode.equals("FORCE_PEER")) {
            this.verifyMode = SslClientVerifyMode.FORCE_PEER;
        } else if (verifyMode.equals("PEER")) {
            this.verifyMode = SslClientVerifyMode.VERIFY_PEER;
        }
    }

    public void setProtocols(String[] protocols) {
        if (logger.isDebugEnabled())
            logger.debug("TLS: " + Arrays.toString(protocols));

        this.protocols = protocols;
    }

    public void setHandshakeTimeoutMilliseconds(long handshakeTimeoutMilliseconds) {
        this.handshakeTimeoutMilliseconds = handshakeTimeoutMilliseconds;
    }
}
