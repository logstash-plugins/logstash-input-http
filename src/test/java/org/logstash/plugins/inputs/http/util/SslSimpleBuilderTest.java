package org.logstash.plugins.inputs.http.util;

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.isIn;
import static org.hamcrest.Matchers.nullValue;
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
import static org.logstash.plugins.inputs.http.util.TestUtils.resourcePath;

/**
 * Unit test for {@link SslSimpleBuilder}
 */
class SslSimpleBuilderTest {
    private static final String CERTIFICATE = resourcePath("host.crt");
    private static final String KEY = resourcePath("host.key");
    private static final String KEY_ENCRYPTED = resourcePath("host.enc.key");
    private static final String KEY_ENCRYPTED_PASS = "1234";
    private static final String CA = resourcePath("root-ca.crt");

    @Test
    void testConstructorShouldFailWhenCertificatePathIsInvalid() {
        final IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> new SslSimpleBuilder("foo-bar.crt", KEY_ENCRYPTED, KEY_ENCRYPTED_PASS)
        );

        assertEquals(
                "Certificate file cannot be read. Please confirm the user running Logstash has permissions to read: foo-bar.crt",
                thrown.getMessage()
        );
    }

    @Test
    void testConstructorShouldFailWhenKeyPathIsInvalid() {
        final IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> new SslSimpleBuilder(CERTIFICATE, "invalid.key", KEY_ENCRYPTED_PASS)
        );

        assertEquals(
                "Private key file cannot be read. Please confirm the user running Logstash has permissions to read: invalid.key",
                thrown.getMessage()
        );
    }

    @Test
    void testSetCipherSuitesShouldNotFailIfAllCiphersAreValid() {
        final SslSimpleBuilder sslSimpleBuilder = createSslSimpleBuilder();
        assertDoesNotThrow(() -> sslSimpleBuilder.setCipherSuites(SUPPORTED_CIPHERS.toArray(new String[0])));
    }

    @Test
    void testSetCipherSuitesShouldThrowIfAnyCiphersIsInValid() {
        final SslSimpleBuilder sslSimpleBuilder = createSslSimpleBuilder();
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
        final SslSimpleBuilder sslSimpleBuilder = createSslSimpleBuilder();
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
    void testSetClientAuthentication() {
        final SslSimpleBuilder sslSimpleBuilder = createSslSimpleBuilder();
        final String[] certificateAuthorities = {CA};

        sslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.REQUIRED, certificateAuthorities);

        assertThat(sslSimpleBuilder.getVerifyMode(), is(SslClientVerifyMode.REQUIRED));
        assertThat(Arrays.asList(sslSimpleBuilder.getCertificateAuthorities()), everyItem(isIn(certificateAuthorities)));
    }

    @Test
    void testSetClientAuthenticationWithRequiredAndNoCertAuthorities() {
        assertSetClientAuthenticationThrowsWhenCAIsNullOrEmpty(SslClientVerifyMode.REQUIRED);
    }

    @Test
    void testSetClientAuthenticationWithOptionalAndNoCertAuthorities() {
        assertSetClientAuthenticationThrowsWhenCAIsNullOrEmpty(SslClientVerifyMode.OPTIONAL);
    }

    @Test
    void testSetClientAuthenticationWithNoneAndEmptyCA() {
        final SslSimpleBuilder sslSimpleBuilder = createSslSimpleBuilder();
        sslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.NONE, new String[0]);
        assertThat(sslSimpleBuilder.getVerifyMode(), is(SslClientVerifyMode.NONE));
        assertThat(sslSimpleBuilder.getCertificateAuthorities(), arrayWithSize(0));
    }

    @Test
    void testSetClientAuthenticationWithNoneAndNullCA() {
        final SslSimpleBuilder sslSimpleBuilder = createSslSimpleBuilder();
        sslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.NONE, null);
        assertThat(sslSimpleBuilder.getVerifyMode(), is(SslClientVerifyMode.NONE));
        assertThat(sslSimpleBuilder.getCertificateAuthorities(), nullValue());
    }

    @Test
    void testDefaultVerifyMode() {
        final SslSimpleBuilder sslSimpleBuilder = createSslSimpleBuilder();
        assertThat(sslSimpleBuilder.getVerifyMode(), is(SslClientVerifyMode.NONE));
    }

    private void assertSetClientAuthenticationThrowsWhenCAIsNullOrEmpty(SslClientVerifyMode mode) {
        final SslSimpleBuilder sslSimpleBuilder = createSslSimpleBuilder();
        final String expectedMessage = "Certificate authorities are required to enable client authentication";

        final IllegalArgumentException emptyThrown = assertThrows(
                IllegalArgumentException.class,
                () -> sslSimpleBuilder.setClientAuthentication(mode, new String[0])
        );

        final IllegalArgumentException nullThrown = assertThrows(IllegalArgumentException.class,
                () -> sslSimpleBuilder.setClientAuthentication(mode, null),
                expectedMessage
        );

        assertEquals(expectedMessage, emptyThrown.getMessage());
        assertEquals(expectedMessage, nullThrown.getMessage());
    }

    @Test
    void testSslClientVerifyModeToClientAuth() {
        assertThat(SslClientVerifyMode.REQUIRED.toClientAuth(), is(ClientAuth.REQUIRE));
        assertThat(SslClientVerifyMode.OPTIONAL.toClientAuth(), is(ClientAuth.OPTIONAL));
        assertThat(SslClientVerifyMode.NONE.toClientAuth(), is(ClientAuth.NONE));
    }

    @Test
    void testBuildContextWithNonEncryptedKey() {
        final SslSimpleBuilder sslSimpleBuilder = new SslSimpleBuilder(CERTIFICATE, KEY, null);
        assertDoesNotThrow(sslSimpleBuilder::build);
    }

    @Test
    void testBuildContextWithEncryptedKey() {
        final SslSimpleBuilder sslSimpleBuilder = new SslSimpleBuilder(CERTIFICATE, KEY_ENCRYPTED, "1234");
        assertDoesNotThrow(sslSimpleBuilder::build);
    }

    @Test
    void testBuildContextWhenClientAuthenticationIsRequired() throws Exception {
        final SSLEngine sslEngine = assertSSlEngineFromBuilder(createSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.REQUIRED, new String[]{CA})
        );

        assertTrue(sslEngine.getNeedClientAuth());
        assertFalse(sslEngine.getWantClientAuth());
    }

    @Test
    void testBuildContextWhenClientAuthenticationIsOptional() throws Exception {
        final SSLEngine sslEngine = assertSSlEngineFromBuilder(createSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.OPTIONAL, new String[]{CA})
        );

        assertFalse(sslEngine.getNeedClientAuth());
        assertTrue(sslEngine.getWantClientAuth());
    }

    @Test
    void testBuildContextWhenClientAuthenticationIsNone() throws Exception {
        final SSLEngine sslEngine = assertSSlEngineFromBuilder(createSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.NONE, new String[]{CA}));

        assertFalse(sslEngine.getNeedClientAuth());
        assertFalse(sslEngine.getWantClientAuth());
    }

    @Test
    void testIsClientAuthenticationRequired() {
        final SslSimpleBuilder sslSimpleBuilder = createSslSimpleBuilder();
        final String[] certificateAuthorities = {CA};

        sslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.NONE, certificateAuthorities);
        assertFalse(sslSimpleBuilder.isClientAuthenticationRequired());

        sslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.OPTIONAL, certificateAuthorities);
        assertFalse(sslSimpleBuilder.isClientAuthenticationRequired());

        sslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.REQUIRED, certificateAuthorities);
        assertTrue(sslSimpleBuilder.isClientAuthenticationRequired());
    }

    private SSLEngine assertSSlEngineFromBuilder(SslSimpleBuilder sslSimpleBuilder) throws Exception {
        final SslContext context = sslSimpleBuilder.build();
        assertTrue(context.isServer());

        final SSLEngine sslEngine = context.newEngine(ByteBufAllocator.DEFAULT);
        assertThat(sslEngine.getEnabledCipherSuites(), equalTo(sslSimpleBuilder.getCiphers()));
        assertThat(sslEngine.getEnabledProtocols(), equalTo(sslSimpleBuilder.getProtocols()));

        return sslEngine;
    }

    private SslSimpleBuilder createSslSimpleBuilder() {
        return new SslSimpleBuilder(CERTIFICATE, KEY_ENCRYPTED, KEY_ENCRYPTED_PASS);
    }
}