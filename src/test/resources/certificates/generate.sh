# Warning: do not use the certificates produced by this tool in production. This is for testing purposes only
# CA
openssl genrsa 4096 | openssl pkcs8 -topk8 -nocrypt -out root-ca.key
openssl req -sha256 -x509 -newkey rsa:4096 -nodes -key root-ca.key -sha256 -days 999999 -out root-ca.crt -subj "/C=ES/ST=The Internet/L=The Internet/O=Logstash CA/OU=Logstash/CN=127.0.0.1"
keytool -import -file root-ca.crt -alias rootCA -keystore truststore.jks -noprompt -storepass changeme

# Server
openssl genrsa 4096 | openssl pkcs8 -topk8 -nocrypt -out host.key
openssl req -sha256 -key host.key -newkey rsa:4096 -out host.csr -subj "/C=ES/ST=The Internet/L=The Internet/O=Logstash CA/OU=Logstash/CN=127.0.0.1"
openssl x509 -req -in host.csr -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out host.crt -sha256 -days 999999
openssl pkcs12 -export -out host-keystore.p12 -inkey host.key -in host.crt -certfile root-ca.crt -password pass:changeme
openssl pkcs8 -topk8 -passout "pass:changeme" -in host.key -out host.enc.key

rm -rf ./*.csr
rm -rf ./*.srl