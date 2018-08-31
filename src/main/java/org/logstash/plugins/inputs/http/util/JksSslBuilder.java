package org.logstash.plugins.inputs.http.util;

import io.netty.handler.ssl.SslContextBuilder;


import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import io.netty.handler.ssl.SslContext;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class JksSslBuilder implements SslBuilder {
    private static final String ALGORITHM_SUN_X509 = "SunX509";
    private static final String ALGORITHM = "ssl.KeyManagerFactory.algorithm";
    private final String keyStorePath;
    private final char[] keyStorePassword;

    public JksSslBuilder(String keyStorePath, String keyStorePassword) {
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword.toCharArray();
    }

    public SslContext build() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {
        String algorithm = Security.getProperty(ALGORITHM);
        if (algorithm == null) {
            algorithm = ALGORITHM_SUN_X509;
        }
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keyStorePath), keyStorePassword);
        ts.load(new FileInputStream(keyStorePath), keyStorePassword);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
        kmf.init(ks, keyStorePassword);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
        tmf.init(ts);

        SslContextBuilder builder = SslContextBuilder.forServer(kmf);
        builder.trustManager(tmf);

        return builder.build();
    }
}
