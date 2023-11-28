package org.logstash.plugins.inputs.http.util;

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import org.junit.jupiter.api.Test;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

import static org.elasticsearch.mock.orig.Mockito.spy;
import static org.elasticsearch.mock.orig.Mockito.verify;
import static org.elasticsearch.mock.orig.Mockito.when;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.isIn;
import static org.hamcrest.core.Every.everyItem;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.logstash.plugins.inputs.http.util.SslSimpleBuilder.SUPPORTED_CIPHERS;
import static org.logstash.plugins.inputs.http.util.SslSimpleBuilder.SslClientVerifyMode;
import static org.logstash.plugins.inputs.http.util.SslSimpleBuilder.getDefaultCiphers;
import static org.logstash.plugins.inputs.http.util.TestCertificates.CA;
import static org.logstash.plugins.inputs.http.util.TestCertificates.CERTIFICATE;
import static org.logstash.plugins.inputs.http.util.TestCertificates.KEY;
import static org.logstash.plugins.inputs.http.util.TestCertificates.KEYSTORE;
import static org.logstash.plugins.inputs.http.util.TestCertificates.KEYSTORE_PASSWORD;
import static org.logstash.plugins.inputs.http.util.TestCertificates.KEYSTORE_TYPE;
import static org.logstash.plugins.inputs.http.util.TestCertificates.KEY_ENCRYPTED;
import static org.logstash.plugins.inputs.http.util.TestCertificates.KEY_ENCRYPTED_PASS;
import static org.logstash.plugins.inputs.http.util.TestCertificates.TRUSTSTORE;
import static org.logstash.plugins.inputs.http.util.TestCertificates.TRUSTSTORE_PASSWORD;
import static org.logstash.plugins.inputs.http.util.TestCertificates.TRUSTSTORE_TYPE;
import static org.mockito.Matchers.eq;

/**
 * Unit test for {@link SslSimpleBuilder}
 */
class SslSimpleBuilderTest {

    @Test
    void testWithPemCertificateShouldFailWhenCertificatePathIsInvalid() {
        final IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> SslSimpleBuilder.withPemCertificate("foo-bar.crt", KEY_ENCRYPTED, KEY_ENCRYPTED_PASS)
        );

        assertEquals(
                "Certificate file cannot be read. Please confirm the user running Logstash has permissions to read: foo-bar.crt",
                thrown.getMessage()
        );
    }

    @Test
    void testWithPemCertificateShouldFailWhenKeyPathIsInvalid() {
        final IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> SslSimpleBuilder.withPemCertificate(CERTIFICATE, "invalid.key", KEY_ENCRYPTED_PASS)
        );

        assertEquals(
                "Private key file cannot be read. Please confirm the user running Logstash has permissions to read: invalid.key",
                thrown.getMessage()
        );
    }

    @Test
    void testWithPemCertificateShouldNotFailWithValidConfig() {
        assertDoesNotThrow(this::createPemSslSimpleBuilder);
    }

    @Test
    void testWithKeyStoreShouldFailWhenKeystorePathIsInvalid() {
        final IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> SslSimpleBuilder.withKeyStore(KEYSTORE_TYPE, "foo-bar.jks", KEYSTORE_PASSWORD)
        );

        assertEquals(
                "Keystore file cannot be read. Please confirm the user running Logstash has permissions to read: foo-bar.jks",
                thrown.getMessage()
        );
    }

    @Test
    void testWithKeyStoreShouldNotFailWithValidConfig() {
        assertDoesNotThrow(this::createJksSslSimpleBuilder);
    }

    @Test
    void testWithKeyStoreShouldNotFailWithNullType() throws Exception {
        final SslSimpleBuilder sslSimpleBuilder = SslSimpleBuilder.withKeyStore(null, KEYSTORE, KEYSTORE_PASSWORD);
        assertEquals(KEYSTORE_TYPE, sslSimpleBuilder.getKeyStore().getType());
    }

    @Test
    void testSetCipherSuitesShouldNotFailIfAllCiphersAreValid() {
        final SslSimpleBuilder sslSimpleBuilder = createPemSslSimpleBuilder();
        assertDoesNotThrow(() -> sslSimpleBuilder.setCipherSuites(SUPPORTED_CIPHERS.toArray(new String[0])));
    }

    @Test
    void testSetCipherSuitesShouldThrowIfAnyCiphersIsInValid() {
        final SslSimpleBuilder sslSimpleBuilder = createPemSslSimpleBuilder();
        final String[] ciphers = SUPPORTED_CIPHERS
                .toArray(new String[SUPPORTED_CIPHERS.size() + 1]);

        ciphers[ciphers.length - 1] = "TLS_INVALID_CIPHER";

        final IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> sslSimpleBuilder.setCipherSuites(ciphers)
        );

        assertEquals("Cipher `TLS_INVALID_CIPHER` is not available", thrown.getMessage());
    }

    @Test
    void testSetProtocols() {
        final SslSimpleBuilder sslSimpleBuilder = createPemSslSimpleBuilder();
        assertArrayEquals(new String[]{"TLSv1.2", "TLSv1.3"}, sslSimpleBuilder.getProtocols());

        sslSimpleBuilder.setProtocols(new String[]{"TLSv1.1"});
        assertArrayEquals(new String[]{"TLSv1.1"}, sslSimpleBuilder.getProtocols());

        sslSimpleBuilder.setProtocols(new String[]{"TLSv1.1", "TLSv1.2"});
        assertArrayEquals(new String[]{"TLSv1.1", "TLSv1.2"}, sslSimpleBuilder.getProtocols());
    }

    @Test
    void testGetDefaultCiphers() {
        final String[] defaultCiphers = getDefaultCiphers();
        assertTrue(defaultCiphers.length > 0);

        // Check that default ciphers is the subset of default ciphers of current Java version.
        final SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        final List<String> availableCiphers = Arrays.asList(ssf.getSupportedCipherSuites());
        assertThat(Arrays.asList(defaultCiphers), everyItem(isIn(availableCiphers)));
    }

    @Test
    void testSetCertificateAuthorities() {
        final String[] certificateAuthorities = {CA};

        final SslSimpleBuilder sslSimpleBuilder = createPemSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.REQUIRED)
                .setCertificateAuthorities(certificateAuthorities);

        assertThat(sslSimpleBuilder.getVerifyMode(), is(SslClientVerifyMode.REQUIRED));
        assertThat(Arrays.asList(sslSimpleBuilder.getCertificateAuthorities()), everyItem(isIn(certificateAuthorities)));
    }

    @Test
    void testSetCertificateAuthoritiesWithNoValue() {
        final SslSimpleBuilder sslSimpleBuilder = createPemSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.REQUIRED);

        final IllegalArgumentException emptyThrown  = assertThrows(
                IllegalArgumentException.class,
                ()-> sslSimpleBuilder.setCertificateAuthorities(new String[0])
        );

        final IllegalArgumentException nullThrown  = assertThrows(
                IllegalArgumentException.class,
                ()-> sslSimpleBuilder.setCertificateAuthorities(null)
        );

        final String expectedMessage = "SSL certificate authorities is required";
        assertEquals(expectedMessage, emptyThrown.getMessage());
        assertEquals(expectedMessage, nullThrown.getMessage());
    }

    @Test
    void testSetTrustStoreWithInvalidPath() {
        final SslSimpleBuilder sslSimpleBuilder = createJksSslSimpleBuilder();

        final IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> sslSimpleBuilder.setTrustStore(TRUSTSTORE_TYPE, "trust-me.jks", TRUSTSTORE_PASSWORD)
        );

        assertEquals(
                "Trust Store file cannot be read. Please confirm the user running Logstash has permissions to read: trust-me.jks",
                thrown.getMessage()
        );
    }

    @Test
    void testSetTrustStoreWithValidArguments() {
        assertDoesNotThrow(() -> createPemSslSimpleBuilder().setTrustStore(TRUSTSTORE_TYPE, TRUSTSTORE, TRUSTSTORE_PASSWORD));
    }

    @Test
    void testSetTrustStoreWithNullTrustStoreType() throws Exception {
        final SslSimpleBuilder sslSimpleBuilder = createPemSslSimpleBuilder()
                .setTrustStore(null, TRUSTSTORE, TRUSTSTORE_PASSWORD);
        assertEquals(TRUSTSTORE_TYPE, sslSimpleBuilder.getTrustStore().getType());
    }

    @Test
    void testSetTrustStoreWithNoTrustedCertificate() {
        assertThrows(
                IllegalArgumentException.class,
                () -> createPemSslSimpleBuilder()
                        .setClientAuthentication(SslClientVerifyMode.REQUIRED)
                        .setTrustStore(KEYSTORE_TYPE, KEYSTORE, KEYSTORE_PASSWORD),
                String.format("The provided Trust Store file does not contains any trusted certificate entry: %s", KEYSTORE)
        );
    }

    @Test
    void testDefaultVerifyModeIsNone() {
        final SslSimpleBuilder sslSimpleBuilder = createPemSslSimpleBuilder();
        assertThat(sslSimpleBuilder.getVerifyMode(), is(SslClientVerifyMode.NONE));
    }

    @Test
    void testSslClientVerifyModeToClientAuth() {
        assertThat(SslClientVerifyMode.REQUIRED.toClientAuth(), is(ClientAuth.REQUIRE));
        assertThat(SslClientVerifyMode.OPTIONAL.toClientAuth(), is(ClientAuth.OPTIONAL));
        assertThat(SslClientVerifyMode.NONE.toClientAuth(), is(ClientAuth.NONE));
    }

    @Test
    void testBuildContextWithNonEncryptedCertificateKey() {
        final SslSimpleBuilder sslSimpleBuilder = SslSimpleBuilder.withPemCertificate(CERTIFICATE, KEY, null);
        assertDoesNotThrow(sslSimpleBuilder::build);
    }

    @Test
    void testBuildContextWithEncryptedCertificateKey() {
        final SslSimpleBuilder sslSimpleBuilder = SslSimpleBuilder.withPemCertificate(CERTIFICATE, KEY_ENCRYPTED, KEY_ENCRYPTED_PASS);
        assertDoesNotThrow(sslSimpleBuilder::build);
    }

    @Test
    void testBuildContextWithKeyStore() throws Exception {
        final SslSimpleBuilder sslSimpleBuilder = SslSimpleBuilder.withKeyStore(KEYSTORE_TYPE, KEYSTORE, KEYSTORE_PASSWORD);
        assertDoesNotThrow(sslSimpleBuilder::build);
    }

    @Test
    void testBuildContextWithClientAuthenticationRequiredAndCAs() throws Exception {
        final SSLEngine sslEngine = assertSSlEngineFromBuilder(createPemSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.REQUIRED)
                .setCertificateAuthorities(new String[]{CA})
        );

        assertTrue(sslEngine.getNeedClientAuth());
        assertFalse(sslEngine.getWantClientAuth());
    }

    @Test
    void testBuildContextWithClientAuthenticationRequiredAndTrustStore() throws Exception {
        final SSLEngine sslEngine = assertSSlEngineFromBuilder(createPemSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.REQUIRED)
                .setTrustStore(TRUSTSTORE_TYPE, TRUSTSTORE, TRUSTSTORE_PASSWORD)
        );

        assertTrue(sslEngine.getNeedClientAuth());
        assertFalse(sslEngine.getWantClientAuth());
    }

    @Test
    void testBuildContextWithClientAuthenticationOptionalAndCAs() throws Exception {
        final SSLEngine sslEngine = assertSSlEngineFromBuilder(createPemSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.OPTIONAL)
                .setCertificateAuthorities(new String[]{CA})
        );

        assertFalse(sslEngine.getNeedClientAuth());
        assertTrue(sslEngine.getWantClientAuth());
    }

    @Test
    void testBuildContextWithClientAuthenticationOptionalAndTrustStore() throws Exception {
        final SSLEngine sslEngine = assertSSlEngineFromBuilder(createPemSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.OPTIONAL)
                .setTrustStore(TRUSTSTORE_TYPE, TRUSTSTORE, TRUSTSTORE_PASSWORD)
        );

        assertFalse(sslEngine.getNeedClientAuth());
        assertTrue(sslEngine.getWantClientAuth());
    }

    @Test
    void testBuildContextWithClientAuthenticationNone() throws Exception {
        final SSLEngine sslEngine = assertSSlEngineFromBuilder(createPemSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.NONE));

        assertFalse(sslEngine.getNeedClientAuth());
        assertFalse(sslEngine.getWantClientAuth());
    }

    @Test
    void testBuildContextWithClientAuthenticationNoneAndTrustStore() throws Exception {
        final SSLEngine sslEngine = assertSSlEngineFromBuilder(createPemSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.NONE)
                .setTrustStore(TRUSTSTORE_TYPE, TRUSTSTORE, TRUSTSTORE_PASSWORD)
        );

        assertFalse(sslEngine.getNeedClientAuth());
        assertFalse(sslEngine.getWantClientAuth());
    }

    @Test
    void testBuildContextWithClientAuthenticationAndKeyStoreAsTrustStore() throws Exception {
        final SSLEngine sslEngine = assertSSlEngineFromBuilder(createJksSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.REQUIRED)
        );

        assertTrue(sslEngine.getNeedClientAuth());
        assertFalse(sslEngine.getWantClientAuth());
    }

    @Test
    void testBuildContextWithCAsAndTrustStore() throws Exception {
        final SslSimpleBuilder sslSimpleBuilder = createJksSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.REQUIRED)
                .setCertificateAuthorities(new String[]{CA})
                .setTrustStore(TRUSTSTORE_TYPE, TRUSTSTORE, TRUSTSTORE_PASSWORD);

        final IllegalStateException thrown  = assertThrows(
                IllegalStateException.class,
                sslSimpleBuilder::build
        );

        assertEquals("Use either a bundle of Certificate Authorities or a Trust Store to configure client authentication", thrown.getMessage());
    }

    @Test
    void testBuildContextWithPemCertificateAndNoCAsNeitherTrustStore() {
        final SslSimpleBuilder sslSimpleBuilder = createPemSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.REQUIRED);

        final IllegalStateException thrown  = assertThrows(
                IllegalStateException.class,
                sslSimpleBuilder::build
        );

        assertEquals("Either an SSL certificate or an SSL Trust Store is required when SSL is enabled", thrown.getMessage());
    }

    @Test
    void testIsClientAuthenticationRequired() {
        final SslSimpleBuilder sslSimpleBuilder = createPemSslSimpleBuilder();

        sslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.NONE);
        assertFalse(sslSimpleBuilder.isClientAuthenticationRequired());

        sslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.OPTIONAL);
        assertFalse(sslSimpleBuilder.isClientAuthenticationRequired());

        sslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.REQUIRED);
        assertTrue(sslSimpleBuilder.isClientAuthenticationRequired());
    }

    @Test
    void testClientAuthenticationWithTrustStoreUsesTruststore() throws Exception {
        final SslSimpleBuilder jksSslBuilder = spy(createJksSslSimpleBuilder())
                .setClientAuthentication(SslClientVerifyMode.REQUIRED)
                .setTrustStore(TRUSTSTORE_TYPE, TRUSTSTORE, TRUSTSTORE_PASSWORD);

        final DummyTrustManagerFactorySpi factorySpi = spy(new DummyTrustManagerFactorySpi());
        final TrustManagerFactory trustManagerFactory = new DummyTrustManagerFactory(factorySpi);

        when(jksSslBuilder.getDefaultTrustManagerFactory())
                .thenReturn(trustManagerFactory);

        jksSslBuilder.build();

        verify(factorySpi).engineInit(eq(jksSslBuilder.getTrustStore()));
    }

    @Test
    void testClientAuthenticationUsesKeystoreWhenNoTrustStoreIsConfigured() throws Exception {
        final SslSimpleBuilder jksSslBuilder = spy(createJksSslSimpleBuilder());
        jksSslBuilder.setClientAuthentication(SslClientVerifyMode.REQUIRED);

        final DummyTrustManagerFactorySpi factorySpi = spy(new DummyTrustManagerFactorySpi());
        final TrustManagerFactory trustManagerFactory = new DummyTrustManagerFactory(factorySpi);

        when(jksSslBuilder.getDefaultTrustManagerFactory())
                .thenReturn(trustManagerFactory);

        jksSslBuilder.build();

        verify(factorySpi).engineInit(eq(jksSslBuilder.getKeyStore()));
    }

    @Test
    void testResolveKeyStoreType() {
        assertEquals("PKCS12", SslSimpleBuilder.resolveKeyStoreType(null, Paths.get("dummy.p12")));
        assertEquals("PKCS12", SslSimpleBuilder.resolveKeyStoreType(null, Paths.get("dummy.P12")));

        assertEquals("PKCS12", SslSimpleBuilder.resolveKeyStoreType(null, Paths.get("dummy.pfx")));
        assertEquals("PKCS12", SslSimpleBuilder.resolveKeyStoreType(null, Paths.get("dummy.PfX")));

        assertEquals("PKCS12", SslSimpleBuilder.resolveKeyStoreType(null, Paths.get("dummy.pkcs12")));
        assertEquals("PKCS12", SslSimpleBuilder.resolveKeyStoreType(null, Paths.get("dummy.PKCS12")));

        assertEquals("jks", SslSimpleBuilder.resolveKeyStoreType(null, Paths.get("dummy.anyOther")));

        assertEquals("foo", SslSimpleBuilder.resolveKeyStoreType("foo", Paths.get("foo.p12")));
        assertEquals("bar", SslSimpleBuilder.resolveKeyStoreType("bar", Paths.get("bar.pfx")));
        assertEquals("any", SslSimpleBuilder.resolveKeyStoreType("any", Paths.get("any.pkcs12")));
    }

    private SSLEngine assertSSlEngineFromBuilder(SslSimpleBuilder sslSimpleBuilder) throws Exception {
        final SslContext context = sslSimpleBuilder.build();
        assertTrue(context.isServer());

        final SSLEngine sslEngine = context.newEngine(ByteBufAllocator.DEFAULT);
        assertThat(sslEngine.getEnabledCipherSuites(), equalTo(sslSimpleBuilder.getCiphers()));
        assertThat(sslEngine.getEnabledProtocols(), equalTo(sslSimpleBuilder.getProtocols()));

        return sslEngine;
    }

    private SslSimpleBuilder createPemSslSimpleBuilder() {
        return SslSimpleBuilder.withPemCertificate(CERTIFICATE, KEY_ENCRYPTED, KEY_ENCRYPTED_PASS);
    }

    private SslSimpleBuilder createJksSslSimpleBuilder() {
        try {
            return SslSimpleBuilder.withKeyStore(KEYSTORE_TYPE, KEYSTORE, KEYSTORE_PASSWORD);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static class DummyTrustManagerFactorySpi extends TrustManagerFactorySpi {
        @Override
        public void engineInit(KeyStore ks) {
        }

        @Override
        public void engineInit(ManagerFactoryParameters spec) {

        }

        @Override
        protected TrustManager[] engineGetTrustManagers() {
            return new TrustManager[0];
        }
    }

    private static class DummyTrustManagerFactory extends TrustManagerFactory {
        DummyTrustManagerFactory(TrustManagerFactorySpi spi) {
            super(spi, Security.getProviders()[0], "SunX509");
        }
    }
}