package org.logstash.plugins.inputs.http.util;

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.SslHandler;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public interface SslBuilder {

    SslHandler build(ByteBufAllocator bufferAllocator) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException;

    enum SslClientVerifyMode {
        VERIFY_PEER,
        FORCE_PEER,
    }
}