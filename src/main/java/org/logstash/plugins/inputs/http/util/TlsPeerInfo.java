package org.logstash.plugins.inputs.http.util;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.AttributeKey;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Extracts details of the client certificate presented during a (m)TLS handshake, so they can be
 * handed over to the message handler next to the regular request headers.
 *
 * All the keys of the produced map start with {@link #KEY_PREFIX}. Since they travel in the same map as
 * the request headers, any request header using that prefix is discarded (see {@link #isReservedKey(String)}),
 * which prevents a client from forging them.
 */
public final class TlsPeerInfo {

    public static final String KEY_PREFIX = "tls_peer_";

    /** Separator used to join multi-valued entries (such as subject alternative names). */
    public static final String VALUE_SEPARATOR = "\n";

    private static final AttributeKey<Map<String, String>> CHANNEL_ATTRIBUTE =
            AttributeKey.valueOf(TlsPeerInfo.class, "TLS_PEER_INFO");

    private static final Map<String, String> UNVERIFIED =
            Collections.singletonMap(KEY_PREFIX + "status", "unverified");

    private TlsPeerInfo() {
    }

    public static boolean isReservedKey(final String formattedHeaderName) {
        return formattedHeaderName.startsWith(KEY_PREFIX);
    }

    /**
     * @return the details of the client certificate of the connection: an empty map when the connection is not
     * secured, only a {@code status} of {@code unverified} when the client did not present a certificate. The result is computed once per connection.
     */
    public static Map<String, String> of(final ChannelHandlerContext ctx) {
        final Channel channel = ctx.channel();
        final Map<String, String> cached = channel.attr(CHANNEL_ATTRIBUTE).get();
        if (cached != null) {
            return cached;
        }

        final SslHandler sslHandler = ctx.pipeline().get(SslHandler.class);
        final Map<String, String> info = sslHandler == null ? Collections.emptyMap() : extract(sslHandler.engine().getSession());
        channel.attr(CHANNEL_ATTRIBUTE).set(info);
        return info;
    }

    static Map<String, String> extract(final SSLSession session) {
        final Certificate[] chain;
        try {
            chain = session.getPeerCertificates();
        } catch (SSLPeerUnverifiedException e) {
            return UNVERIFIED; // client authentication is not required and no certificate was presented
        }
        if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate)) {
            return UNVERIFIED;
        }

        final X509Certificate cert = (X509Certificate) chain[0];
        final Map<String, String> info = new HashMap<>();
        info.put(KEY_PREFIX + "status", "verified");
        info.put(KEY_PREFIX + "subject", cert.getSubjectX500Principal().getName());
        info.put(KEY_PREFIX + "issuer_dn", cert.getIssuerX500Principal().getName());
        info.put(KEY_PREFIX + "serial", cert.getSerialNumber().toString(16));
        info.put(KEY_PREFIX + "not_before", cert.getNotBefore().toInstant().toString());
        info.put(KEY_PREFIX + "not_after", cert.getNotAfter().toInstant().toString());
        info.put(KEY_PREFIX + "protocol", session.getProtocol());
        info.put(KEY_PREFIX + "cipher_suite", session.getCipherSuite());

        final String commonName = commonName(cert);
        if (commonName != null) {
            info.put(KEY_PREFIX + "subject_cn", commonName);
        }
        final String fingerprint = sha256Fingerprint(cert);
        if (fingerprint != null) {
            info.put(KEY_PREFIX + "fingerprint_sha256", fingerprint);
        }
        final String sans = subjectAlternativeNames(cert);
        if (sans != null) {
            info.put(KEY_PREFIX + "sans", sans);
        }
        return Collections.unmodifiableMap(info);
    }

    private static String commonName(final X509Certificate cert) {
        try {
            final List<Rdn> rdns = new LdapName(cert.getSubjectX500Principal().getName()).getRdns();
            // LdapName lists the RDNs from the rightmost one; the most specific CN is the leftmost one
            for (int i = rdns.size() - 1; i >= 0; i--) {
                if ("CN".equalsIgnoreCase(rdns.get(i).getType())) {
                    return String.valueOf(rdns.get(i).getValue());
                }
            }
        } catch (InvalidNameException e) {
            // no common name available
        }
        return null;
    }

    private static String sha256Fingerprint(final X509Certificate cert) {
        try {
            final byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            final StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            return null;
        }
    }

    /** @return entries formatted as {@code type:value} (email, dns, uri, ip, dir) joined by {@link #VALUE_SEPARATOR}. */
    private static String subjectAlternativeNames(final X509Certificate cert) {
        final Collection<List<?>> names;
        try {
            names = cert.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            return null;
        }
        if (names == null) {
            return null;
        }

        final List<String> entries = new ArrayList<>();
        for (List<?> name : names) {
            final String type = sanType((Integer) name.get(0));
            if (type != null && name.get(1) instanceof String) {
                entries.add(type + ":" + name.get(1));
            }
        }
        return entries.isEmpty() ? null : String.join(VALUE_SEPARATOR, entries);
    }

    private static String sanType(final int generalNameType) {
        switch (generalNameType) {
            case 1: return "email";
            case 2: return "dns";
            case 4: return "dir";
            case 6: return "uri";
            case 7: return "ip";
            default: return null; // otherName, x400, ediParty, registeredID: not representable as text
        }
    }
}
