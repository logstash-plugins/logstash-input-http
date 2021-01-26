package org.logstash.plugins.inputs.http.util;

import io.netty.handler.ssl.SslContext;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public interface SslBuilder {

    /**
     * @return context
     * @throws Exception (IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException)
     */
    SslContext build() throws Exception;

}