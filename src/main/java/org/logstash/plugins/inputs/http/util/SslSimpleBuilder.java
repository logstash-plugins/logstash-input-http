package org.logstash.plugins.inputs.http.util;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;

public class SslSimpleBuilder implements SslBuilder {

    private final static Logger logger = LogManager.getLogger(SslSimpleBuilder.class);

    /*
    Modern Ciphers Compatibility List from
    https://wiki.mozilla.org/Security/Server_Side_TLS
    */
    private final static String[] DEFAULT_CIPHERS = new String[] {
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
    };

    private final static String[] DEFAULT_CIPHERS_LIMITED = new String[] {
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
    };

    private String[] ciphers = getDefaultCiphers();
    private File sslKeyFile;
    private File sslCertificateFile;
    private String[] certificateAuthorities;
    private String passPhrase;
    private String[] supportedCiphers = ((SSLServerSocketFactory)SSLServerSocketFactory
            .getDefault()).getSupportedCipherSuites();

    public SslSimpleBuilder(String sslCertificateFilePath, String sslKeyFilePath, String pass) throws FileNotFoundException {
        sslCertificateFile = new File(sslCertificateFilePath);
        sslKeyFile = new File(sslKeyFilePath);
        passPhrase = pass;
    }

    public SslSimpleBuilder setCipherSuites(String[] ciphersSuite) throws IllegalArgumentException {
        for(String cipher : ciphersSuite) {
            if(Arrays.asList(supportedCiphers).contains(cipher)) {
                logger.debug("Cipher is supported: {}", cipher);
            }else{
                if (!isUnlimitedJCEAvailable()) {
                    logger.warn("JCE Unlimited Strength Jurisdiction Policy not installed");
                }
                throw new IllegalArgumentException("Cipher `" + cipher + "` is not available");
            }
        }

        ciphers = ciphersSuite;
        return this;
    }

    public SslSimpleBuilder setCertificateAuthorities(String[] cert) {
        certificateAuthorities = cert;
        return this;
    }

    public SslContext build() throws Exception {
        SslContextBuilder builder = SslContextBuilder.forServer(sslCertificateFile, sslKeyFile, passPhrase);

        if(logger.isDebugEnabled()) {
            logger.debug("Available ciphers: " + Arrays.toString(supportedCiphers));
            logger.debug("Ciphers:  " + Arrays.toString(ciphers));
        }

        builder.ciphers(Arrays.asList(ciphers));

        if(requireClientAuth()) {
            if (logger.isDebugEnabled())
                logger.debug("Certificate Authorities: " + Arrays.toString(certificateAuthorities));

            builder.trustManager(loadCertificateCollection(certificateAuthorities));
        }

        return doBuild(builder);
    }

    // NOTE: copy-pasta from input-beats
    static SslContext doBuild(final SslContextBuilder builder) throws Exception {
        try {
            return builder.build();
        } catch (SSLException e) {
            logger.debug("Failed to initialize SSL", e);
            // unwrap generic wrapped exception from Netty's JdkSsl{Client|Server}Context
            if ("failed to initialize the server-side SSL context".equals(e.getMessage()) ||
                "failed to initialize the client-side SSL context".equals(e.getMessage())) {
                // Netty catches Exception and simply wraps: throw new SSLException("...", e);
                if (e.getCause() instanceof Exception) throw (Exception) e.getCause();
            }
            throw e;
        } catch (Exception e) {
            logger.debug("Failed to initialize SSL", e);
            throw e;
        }
    }

    private X509Certificate[] loadCertificateCollection(String[] certificates) throws IOException, CertificateException {
        logger.debug("Load certificates collection");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        List<X509Certificate> collections = new ArrayList<X509Certificate>();

        for(int i = 0; i < certificates.length; i++) {
            String certificate = certificates[i];

            logger.debug("Loading certificates from file " + certificate);

            try(InputStream in = new FileInputStream(certificate)) {
                List<X509Certificate> certificatesChains = (List<X509Certificate>) certificateFactory.generateCertificates(in);
                collections.addAll(certificatesChains);
            }
        }
        return collections.toArray(new X509Certificate[collections.size()]);
    }

    private boolean requireClientAuth() {
        if(certificateAuthorities != null) {
            return true;
        }

        return false;
    }

    public static String[] getDefaultCiphers(){
        if (isUnlimitedJCEAvailable()){
            return DEFAULT_CIPHERS;
        } else {
            logger.warn("JCE Unlimited Strength Jurisdiction Policy not installed - max key length is 128 bits");
            return DEFAULT_CIPHERS_LIMITED;
        }
    }


    public static boolean isUnlimitedJCEAvailable(){
        try {
            return (Cipher.getMaxAllowedKeyLength("AES") > 128);
        } catch (NoSuchAlgorithmException e) {
            logger.warn("AES not available", e);
            return false;
        }
    }

}
