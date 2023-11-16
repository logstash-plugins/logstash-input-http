package org.logstash.plugins.inputs.http.util;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import javax.crypto.Cipher;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class SslSimpleBuilder implements SslBuilder {

    public enum SslClientVerifyMode {
        NONE(ClientAuth.NONE),
        OPTIONAL(ClientAuth.OPTIONAL),
        REQUIRED(ClientAuth.REQUIRE);

        private final ClientAuth clientAuth;

        SslClientVerifyMode(ClientAuth clientAuth) {
            this.clientAuth = clientAuth;
        }

        public ClientAuth toClientAuth() {
            return clientAuth;
        }
    }

    private final static Logger logger = LogManager.getLogger(SslSimpleBuilder.class);

    public static final Set<String> SUPPORTED_CIPHERS = new HashSet<>(Arrays.asList(
        ((SSLServerSocketFactory) SSLServerSocketFactory.getDefault()).getSupportedCipherSuites()
    ));

    /*
    Ciphers Compatibility List from https://wiki.mozilla.org/Security/Server_Side_TLS
    */
    private final static String[] DEFAULT_CIPHERS;
    static {
        String[] defaultCipherCandidates = new String[] {
            // Modern compatibility
            "TLS_AES_256_GCM_SHA384", // TLS 1.3
            "TLS_AES_128_GCM_SHA256", // TLS 1.3
            "TLS_CHACHA20_POLY1305_SHA256", // TLS 1.3 (since Java 11.0.14)
            // Intermediate compatibility
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", // (since Java 11.0.14)
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", // (since Java 11.0.14)
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            // Backward compatibility
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
        };
        DEFAULT_CIPHERS = Arrays.stream(defaultCipherCandidates).filter(SUPPORTED_CIPHERS::contains).toArray(String[]::new);
    }

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

    private String[] protocols = new String[] { "TLSv1.2", "TLSv1.3" };
    private String[] ciphers = getDefaultCiphers();
    private File sslKeyFile;
    private File sslCertificateFile;
    private String[] certificateAuthorities;
    private KeyStore keyStore;
    private char[] keyStorePassword;
    private KeyStore trustStore;
    private String passphrase;
    private SslClientVerifyMode verifyMode = SslClientVerifyMode.NONE;

    public static SslSimpleBuilder withPemCertificate(String sslCertificateFilePath, String sslKeyFilePath, String pass) {
        SslSimpleBuilder builder = new SslSimpleBuilder();

        builder.sslCertificateFile = new File(sslCertificateFilePath);
        if (!builder.sslCertificateFile.canRead()) {
            throw new IllegalArgumentException(
                    String.format("Certificate file cannot be read. Please confirm the user running Logstash has permissions to read: %s", sslCertificateFilePath));
        }

        builder.sslKeyFile = new File(sslKeyFilePath);
        if (!builder.sslKeyFile.canRead()) {
            throw new IllegalArgumentException(
                    String.format("Private key file cannot be read. Please confirm the user running Logstash has permissions to read: %s", sslKeyFilePath));
        }

        builder.passphrase = pass;
        return builder;
    }

    public static SslSimpleBuilder withKeyStore(String keyStoreType, String keyStoreFile, String keyStorePassword) throws Exception {
        SslSimpleBuilder builder = new SslSimpleBuilder();
        final Path keyStorePath = Paths.get(Objects.requireNonNull(keyStoreFile, "Keystore path cannot be null"));
        if (!Files.isReadable(keyStorePath)) {
            throw new IllegalArgumentException(String.format("Keystore file cannot be read. Please confirm the user running Logstash has permissions to read: %s", keyStoreFile));
        }

        builder.keyStorePassword = formatJksPassword(keyStorePassword);
        builder.keyStore = readKeyStore(keyStorePath, resolveKeyStoreType(keyStoreType, keyStorePath), builder.keyStorePassword);
        return builder;
    }

    private SslSimpleBuilder() {
    }

    public SslSimpleBuilder setProtocols(String[] protocols) {
        this.protocols = protocols;
        return this;
    }

    public SslSimpleBuilder setCipherSuites(String[] ciphersSuite) throws IllegalArgumentException {
        for (String cipher : ciphersSuite) {
            if (SUPPORTED_CIPHERS.contains(cipher)) {
                logger.debug("{} cipher is supported", cipher);
            } else {
                if (!isUnlimitedJCEAvailable()) {
                    logger.warn("JCE Unlimited Strength Jurisdiction Policy not installed");
                }
                throw new IllegalArgumentException("Cipher `" + cipher + "` is not available");
            }
        }

        ciphers = ciphersSuite;
        return this;
    }

    public SslSimpleBuilder setClientAuthentication(SslClientVerifyMode verifyMode) {
        this.verifyMode = verifyMode;
        return this;
    }

    public SslSimpleBuilder setCertificateAuthorities(String[] certificateAuthorities) {
        if (certificateAuthorities == null || certificateAuthorities.length == 0){
            throw new IllegalArgumentException("SSL certificate authorities is required");
        }

        this.certificateAuthorities = certificateAuthorities;
        return this;
    }

    public SslSimpleBuilder setTrustStore(String trustStoreType, String trustStoreFile, String trustStorePassword) throws Exception {
        final Path trustStorePath = Paths.get(Objects.requireNonNull(trustStoreFile, "Trust Store path cannot be null"));
        if (!Files.isReadable(trustStorePath)) {
            throw new IllegalArgumentException(String.format("Trust Store file cannot be read. Please confirm the user running Logstash has permissions to read: %s", trustStoreFile));
        }

        this.trustStore = readKeyStore(
                trustStorePath,
                resolveKeyStoreType(trustStoreType, trustStorePath),
                formatJksPassword(trustStorePassword)
        );

        if (!hasTrustStoreEntry(this.trustStore)) {
            logger.warn("The provided Trust Store file does not contains any trusted certificate entry: {}. Please confirm this is the correct certificate and the password is correct", trustStoreFile);
        }

        return this;
    }

    private boolean isClientAuthenticationEnabled(final SslClientVerifyMode mode) {
        return mode == SslClientVerifyMode.OPTIONAL || mode == SslClientVerifyMode.REQUIRED;
    }

    public boolean isClientAuthenticationRequired() {
        return verifyMode == SslClientVerifyMode.REQUIRED;
    }

    public SslContext build() throws Exception {
        if (this.trustStore != null && this.certificateAuthorities != null) {
            throw new IllegalStateException("Use either an SSL certificate authorities or a Trust Store to configure client authentication");
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Available ciphers: {}", SUPPORTED_CIPHERS);
            logger.debug("Ciphers: {}", Arrays.toString(ciphers));
        }

        SslContextBuilder builder = createSslContextBuilder()
                .ciphers(Arrays.asList(ciphers))
                .protocols(protocols)
                .clientAuth(verifyMode.toClientAuth());

        if (isClientAuthenticationEnabled(verifyMode)) {
            if (certificateAuthorities != null) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Certificate Authorities: {}", Arrays.toString(certificateAuthorities));
                }

                builder.trustManager(loadCertificateCollection(certificateAuthorities));
            } else if (trustStore != null || keyStore != null) {
                builder.trustManager(createTrustManagerFactory());
            } else {
                throw new IllegalStateException("Either an SSL certificate or an SSL Trust Store is required when SSL is enabled");
            }
        }

        return doBuild(builder);
    }

    private SslContextBuilder createSslContextBuilder() throws Exception {
        if (sslCertificateFile != null) {
            return SslContextBuilder.forServer(sslCertificateFile, sslKeyFile, passphrase);
        }

        if (keyStore != null) {
            return SslContextBuilder.forServer(createKeyManagerFactory());
        }

        throw new IllegalStateException("Either an KeyStore or an SSL certificate must be provided");
    }

    private KeyManagerFactory createKeyManagerFactory() throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        final KeyManagerFactory kmf = getDefaultKeyManagerFactory();
        kmf.init(this.keyStore, this.keyStorePassword);
        return kmf;
    }

    KeyManagerFactory getDefaultKeyManagerFactory() throws NoSuchAlgorithmException {
        return KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    }

    private TrustManagerFactory createTrustManagerFactory() throws Exception {
        final TrustManagerFactory tmf = getDefaultTrustManagerFactory();
        if (this.trustStore == null) {
            logger.info("SSL Trust Store not configured, using the provided Key Store instead.");

            if (logger.isDebugEnabled() && !hasTrustStoreEntry(this.keyStore)) {
                logger.debug("The provided SSL Key Store, used as Trust Store, has no trusted certificate entry.");
            }

            tmf.init(this.keyStore);
            return tmf;
        }

        tmf.init(this.trustStore);
        return tmf;
    }

    TrustManagerFactory getDefaultTrustManagerFactory() throws NoSuchAlgorithmException {
        return TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
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

        final List<X509Certificate> collections = new ArrayList<>();

        for (String certificate : certificates) {
            logger.debug("Loading certificates from file {}", certificate);

            try (InputStream in = new FileInputStream(certificate)) {
                List<X509Certificate> certificatesChains = (List<X509Certificate>) certificateFactory.generateCertificates(in);
                collections.addAll(certificatesChains);
            }
        }
        return collections.toArray(new X509Certificate[collections.size()]);
    }

    public static String[] getDefaultCiphers() {
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

    String[] getProtocols() {
        return protocols != null ? protocols.clone() : null;
    }

    String[] getCertificateAuthorities() {
        return certificateAuthorities != null ? certificateAuthorities.clone() : null;
    }

    String[] getCiphers() {
        return ciphers != null ? ciphers.clone() : null;
    }

    SslClientVerifyMode getVerifyMode() {
        return verifyMode;
    }

    static String resolveKeyStoreType(String type, Path path) {
        if (type == null || type.isEmpty()) {
            return inferKeyStoreType(path);
        }
        return type;
    }

    private static String inferKeyStoreType(Path path) {
        String name = path == null ? "" : path.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith(".p12") || name.endsWith(".pfx") || name.endsWith(".pkcs12")) {
            return "PKCS12";
        } else {
            return "jks";
        }
    }

    private static char[] formatJksPassword(String password) {
        if (password == null){
            return null;
        }

        return password.toCharArray();
    }

    private static KeyStore readKeyStore(Path path, String ksType, char[] password) throws GeneralSecurityException, IOException {
        final KeyStore keyStore = KeyStore.getInstance(ksType);
        if (path != null) {
            try (InputStream in = Files.newInputStream(path)) {
                keyStore.load(in, password);
            }
        }
        return keyStore;
    }

    private boolean hasTrustStoreEntry(KeyStore store) throws GeneralSecurityException {
        Enumeration<String> aliases = store.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (store.isCertificateEntry(alias)) {
                return true;
            }
        }

        return false;
    }

    KeyStore getKeyStore() {
        return keyStore;
    }

    KeyStore getTrustStore() {
        return trustStore;
    }
}
