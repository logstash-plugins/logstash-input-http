package org.logstash.plugins.inputs.http.util;

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import org.hamcrest.core.Every;
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
        final SslSimpleBuilder SslSimpleBuilder = createSslSimpleBuilder();
        assertDoesNotThrow(()-> SslSimpleBuilder.setCipherSuites(SUPPORTED_CIPHERS.toArray(new String[0])));
    }

    @Test
    void testSetCipherSuitesShouldThrowIfAnyCiphersIsInValid() {
        final SslSimpleBuilder SslSimpleBuilder = createSslSimpleBuilder();
        final String[] ciphers = SUPPORTED_CIPHERS
                .toArray(new String[SUPPORTED_CIPHERS.size() + 1]);

        ciphers[ciphers.length - 1] = "TLS_INVALID_CIPHER";

        final IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> SslSimpleBuilder.setCipherSuites(ciphers)
        );

        assertEquals("Cipher `TLS_INVALID_CIPHER` is not available", thrown.getMessage());
    }

    @Test
    void testSetProtocols() {
        final SslSimpleBuilder SslSimpleBuilder = createSslSimpleBuilder();
        assertArrayEquals(new String[]{"TLSv1.2", "TLSv1.3"}, SslSimpleBuilder.getProtocols());

        SslSimpleBuilder.setProtocols(new String[]{"TLSv1.1"});
        assertArrayEquals(new String[]{"TLSv1.1"}, SslSimpleBuilder.getProtocols());

        SslSimpleBuilder.setProtocols(new String[]{"TLSv1.1", "TLSv1.2"});
        assertArrayEquals(new String[]{"TLSv1.1", "TLSv1.2"}, SslSimpleBuilder.getProtocols());
    }

    @Test
    void testGetDefaultCiphers() {
        final String[] defaultCiphers = getDefaultCiphers();
        assertTrue(defaultCiphers.length > 0);

        // Check that default ciphers is the subset of default ciphers of current Java version.
        final SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        final List<String> availableCiphers = Arrays.asList(ssf.getSupportedCipherSuites());
        assertThat(Arrays.asList(defaultCiphers), Every.everyItem(isIn(availableCiphers)));
    }

    @Test
    void testSetClientAuthentication() {
        final SslSimpleBuilder SslSimpleBuilder = createSslSimpleBuilder();
        final String[] certificateAuthorities = {CA};

        SslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.REQUIRED, certificateAuthorities);

        assertThat(SslSimpleBuilder.getVerifyMode(), is(SslClientVerifyMode.REQUIRED));
        assertThat(Arrays.asList(SslSimpleBuilder.getCertificateAuthorities()), Every.everyItem(isIn(certificateAuthorities)));
    }

    @Test
    void testSetClientAuthenticationWithRequiredAndNoCertAuthorities() {
        assertSetClientAuthenticationThrowWithNoCerts(SslClientVerifyMode.REQUIRED);
    }

    @Test
    void testSetClientAuthenticationWithOptionalAndNoCertAuthorities() {
        assertSetClientAuthenticationThrowWithNoCerts(SslClientVerifyMode.OPTIONAL);
    }

    @Test
    void testSetClientAuthenticationWithNone() {
        final SslSimpleBuilder SslSimpleBuilder = createSslSimpleBuilder();

        SslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.NONE, new String[0]);
        assertThat(SslSimpleBuilder.getVerifyMode(), is(SslClientVerifyMode.NONE));
        assertThat(SslSimpleBuilder.getCertificateAuthorities(), arrayWithSize(0));

        SslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.NONE, null);
        assertThat(SslSimpleBuilder.getVerifyMode(), is(SslClientVerifyMode.NONE));
        assertThat(SslSimpleBuilder.getCertificateAuthorities(), nullValue());
    }

    @Test
    void testDefaultVerifyMode() {
        final SslSimpleBuilder SslSimpleBuilder = createSslSimpleBuilder();
        assertThat(SslSimpleBuilder.getVerifyMode(), is(SslClientVerifyMode.NONE));
    }

    private void assertSetClientAuthenticationThrowWithNoCerts(SslClientVerifyMode mode) {
        final SslSimpleBuilder SslSimpleBuilder = createSslSimpleBuilder();
        final String expectedMessage = "Certificate authorities are required to enable client authentication";

        final IllegalArgumentException emptyThrown = assertThrows(
                IllegalArgumentException.class,
                () -> SslSimpleBuilder.setClientAuthentication(mode, new String[0])
        );

        final IllegalArgumentException nullThrown = assertThrows(IllegalArgumentException.class,
                () -> SslSimpleBuilder.setClientAuthentication(mode, null),
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
    void testBuildContextWithNonEncryptedKey() throws Exception {
        final SslSimpleBuilder sslSimpleBuilder = new SslSimpleBuilder(CERTIFICATE, KEY, null);
        assertDoesNotThrow(sslSimpleBuilder::build);
    }

    @Test
    void testBuildContextWithEncryptedKey() throws Exception {
        final SslSimpleBuilder sslSimpleBuilder = new SslSimpleBuilder(CERTIFICATE, KEY_ENCRYPTED, "1234");
        assertDoesNotThrow(sslSimpleBuilder::build);
    }

    @Test
    void testBuildContextWithClientAuthentication() throws Exception {
        assertSslSimpleBuilderBuildContext(createSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.REQUIRED, new String[]{CA})
        );

        assertSslSimpleBuilderBuildContext(createSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.OPTIONAL, new String[]{CA})
        );
    }

    @Test
    void testBuildContextWithNoClientAuthentication() throws Exception {
        SslSimpleBuilder SslSimpleBuilder = createSslSimpleBuilder()
                .setClientAuthentication(SslClientVerifyMode.NONE, new String[]{CA});

        assertSslSimpleBuilderBuildContext(SslSimpleBuilder);
    }

    @Test
    void testIsClientAuthenticationRequired() {
        final SslSimpleBuilder SslSimpleBuilder = createSslSimpleBuilder();
        final String[] certificateAuthorities = {CA};

        SslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.NONE, certificateAuthorities);
        assertFalse(SslSimpleBuilder.isClientAuthenticationRequired());

        SslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.OPTIONAL, certificateAuthorities);
        assertFalse(SslSimpleBuilder.isClientAuthenticationRequired());

        SslSimpleBuilder.setClientAuthentication(SslClientVerifyMode.REQUIRED, certificateAuthorities);
        assertTrue(SslSimpleBuilder.isClientAuthenticationRequired());
    }

    private void assertSslSimpleBuilderBuildContext(SslSimpleBuilder SslSimpleBuilder) throws Exception {
        final SslContext context = SslSimpleBuilder.build();

        assertTrue(context.isServer());

        final SSLEngine sslEngine = context.newEngine(ByteBufAllocator.DEFAULT);
        assertThat(sslEngine.getEnabledCipherSuites(), equalTo(SslSimpleBuilder.getCiphers()));
        assertThat(sslEngine.getEnabledProtocols(), equalTo(SslSimpleBuilder.getProtocols()));

        if (SslSimpleBuilder.getVerifyMode() == SslClientVerifyMode.NONE) {
            assertFalse(sslEngine.getNeedClientAuth());
            assertFalse(sslEngine.getWantClientAuth());
        } else if (SslSimpleBuilder.getVerifyMode() == SslClientVerifyMode.OPTIONAL) {
            assertFalse(sslEngine.getNeedClientAuth());
            assertTrue(sslEngine.getWantClientAuth());
        } else {
            assertTrue(sslEngine.getNeedClientAuth());
            assertFalse(sslEngine.getWantClientAuth());
        }
    }

    private SslSimpleBuilder createSslSimpleBuilder() {
        return new SslSimpleBuilder(CERTIFICATE, KEY_ENCRYPTED, KEY_ENCRYPTED_PASS);
    }
}