package org.logstash.plugins.inputs.http.util;

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collections;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TlsPeerInfoTest {

    private static Certificate loadCertificate(String path) throws Exception {
        try (InputStream in = new FileInputStream(path)) {
            return CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    @Test
    void extractsTheDetailsOfThePeerCertificate() throws Exception {
        final SSLSession session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenReturn(new Certificate[]{loadCertificate(TestCertificates.CERTIFICATE)});
        when(session.getProtocol()).thenReturn("TLSv1.3");
        when(session.getCipherSuite()).thenReturn("TLS_AES_128_GCM_SHA256");

        final Map<String, String> info = TlsPeerInfo.extract(session);

        assertThat(info, hasEntry("tls_peer_status", "verified"));
        assertThat(info, hasEntry("tls_peer_subject_cn", "127.0.0.1"));
        assertThat(info, hasEntry("tls_peer_subject", "CN=127.0.0.1,OU=Logstash,O=Logstash CA,L=The Internet,ST=The Internet,C=ES"));
        assertThat(info, hasEntry("tls_peer_issuer_dn", "CN=127.0.0.1,OU=Logstash,O=Logstash CA,L=The Internet,ST=The Internet,C=ES"));
        assertThat(info, hasEntry("tls_peer_serial", "15db76aea4e4eecd3d7543bdaf2e32aed553c665"));
        assertThat(info, hasEntry("tls_peer_protocol", "TLSv1.3"));
        assertThat(info, hasEntry("tls_peer_cipher_suite", "TLS_AES_128_GCM_SHA256"));
        assertThat(info.get("tls_peer_fingerprint_sha256"), matchesPattern("[0-9a-f]{64}"));
        assertThat(info.get("tls_peer_not_before"), matchesPattern("\\d{4}-\\d\\d-\\d\\dT.*Z"));
        assertThat(info.get("tls_peer_not_after"), matchesPattern("\\d{4}-\\d\\d-\\d\\dT.*Z"));
        assertThat(info.containsKey("tls_peer_sans"), equalTo(false)); // the certificate has no extension
        assertThat(info.keySet(), everyItem(startsWith(TlsPeerInfo.KEY_PREFIX)));
    }

    @Test
    void isUnverifiedWhenTheClientDidNotPresentACertificate() throws Exception {
        final SSLSession session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenThrow(new SSLPeerUnverifiedException("peer not authenticated"));

        assertThat(TlsPeerInfo.extract(session), equalTo(Collections.singletonMap("tls_peer_status", "unverified")));
    }

    @Test
    void reservesTheKeysUsedForTheDetails() {
        assertThat(TlsPeerInfo.isReservedKey("tls_peer_subject_cn"), equalTo(true));
        assertThat(TlsPeerInfo.isReservedKey("request_path"), not(equalTo(true)));
    }
}
