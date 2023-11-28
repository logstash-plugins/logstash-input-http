package org.logstash.plugins.inputs.http.util;

import static org.logstash.plugins.inputs.http.util.TestUtils.resourcePath;

interface TestCertificates {
    String CERTIFICATE = resourcePath("certificates/host.crt");
    String KEY = resourcePath("certificates/host.key");
    String KEY_ENCRYPTED = resourcePath("certificates/host.enc.key");
    String KEY_ENCRYPTED_PASS = "changeme";
    String CA = resourcePath("certificates/root-ca.crt");


    String KEYSTORE = resourcePath("certificates/host-keystore.p12");
    String KEYSTORE_TYPE = "PKCS12";
    String KEYSTORE_PASSWORD = "changeme";


    String TRUSTSTORE = resourcePath("certificates/truststore.jks");
    String TRUSTSTORE_TYPE = "jks";
    String TRUSTSTORE_PASSWORD = "changeme";
}
