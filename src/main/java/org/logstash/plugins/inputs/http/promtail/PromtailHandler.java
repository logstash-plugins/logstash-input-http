package org.logstash.plugins.inputs.http.promtail;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.Timestamp;
import org.xerial.snappy.Snappy;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import static java.time.format.DateTimeFormatter.ISO_INSTANT;

public class PromtailHandler {

    /**
     * Used in Ruby code to properly decode bytes to Java String.
     * @param bytes
     * @return
     */
    public String toUTF8String(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /**
     * Decodes Promtail message. See https://github.com/grafana/loki/blob/main/pkg/logproto/logproto.proto
     * Decodes and return map with fields
     * - message: log line received from Loki
     * - @timestamp: ISO-8601 encoded date as String
     * - *: log labels set by promtail
     *
     * @param payload received from Promtail
     * @return Map with label values consumable by Logstash.
     * @throws Exception
     */
    public List<Map<String, String>> decode(byte[] payload) throws Exception {
        byte[] uncompressed = Snappy.uncompress(payload);
        return parseMap(Logproto.PushRequest.parseFrom(uncompressed));
    }

    private List<Map<String, String>> parseMap(Logproto.PushRequest pushRequest) {

        List<Map<String, String>> out = new ArrayList<>();
        final ObjectMapper mapper = new ObjectMapper();
        mapper.configure(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES, true);

        for (Logproto.StreamAdapter stream : pushRequest.getStreamsList()) {
            Map<String, String> labels = parse(stream.getLabels(), mapper);

            for (Logproto.EntryAdapter entry : stream.getEntriesList()) {
                Map<String, String> event = new HashMap<>(labels);
                if (entry.hasTimestamp()) {
                    event.put("@timestamp", ISO_INSTANT.format(Instant.ofEpochSecond(entry.getTimestamp().getSeconds())));
                }

                event.put("message", entry.getLine());
                out.add(event);
            }

        }
        return out;
    }

    /**
     * Parses json message to map.
     *
     * @param json sting encoded json
     * @param mapper mapper. Set proper option to handle special cases used in Go (ie. ALLOW_UNQUOTED_FIELD_NAMES)
     * @return
     */
    public Map<String, String> parse(String json, ObjectMapper mapper) {
        try {
            if (json == null || json.isEmpty())
                return Collections.EMPTY_MAP;
            json = json.replaceAll("=\"", ":\"");
            return mapper.readValue(json, Map.class);
        } catch (JsonProcessingException e) {
            Map<String, String> event = new HashMap<>();
            event.put("labels_all", json);
            event.put("error", e.getMessage());
            return event;
        }
    }

    /**
     * Method used in test only. Timestamp is hardcoded.
     * Needs refactoring to use it in production:
     * - hardcoded timestamp
     * - no labels handling
     * - minimal Logproto information used
     *
     * @param message Log line
     * @return Snappy-Compressed Loki Logproto. See https://github.com/grafana/loki/blob/main/pkg/logproto/logproto.proto
     * @throws IOException
     */
    public String compress(String message) throws IOException {
        Logproto.PushRequest pushRequest = Logproto.PushRequest.newBuilder()
                .addStreams(Logproto.StreamAdapter.newBuilder().addEntries(
                        Logproto.EntryAdapter.newBuilder().setTimestamp(Timestamp.newBuilder().setSeconds(200).build())
                                .setLine(message)
                                .build())).build();

        return new String(Snappy.compress(pushRequest.toByteArray()), StandardCharsets.ISO_8859_1);
    }

    /**
     * To support snappy-compressed http request in tests.
     * Sets the following request properties:
     * - Loki standard protobuf protocol. See https://github.com/grafana/loki/blob/main/pkg/logproto/logproto.proto
     *  Content-Type: application/x-protobuf
     * - Loki tenant separation. See https://grafana.com/docs/loki/latest/operations/multi-tenancy/
     *  X-Scope-OrgID: tenant
     * - POST to Loki push endpoint. See https://grafana.com/docs/loki/latest/api/#post-lokiapiv1push
     *
     * Needs refactoring to use it in production code.
     * compress(...) method uses hardoced timestamp value
     *
     * @param uri
     * @param message
     * @param tenant
     * @return
     * @throws IOException
     */
    public String sendLogHttp(String uri, String message, String tenant) throws IOException {

        String ret = "OK";

        URL url = new URL(uri);
        URLConnection con = url.openConnection();
        HttpURLConnection http = (HttpURLConnection)con;
        http.setRequestMethod("POST"); // PUT is another valid option
        http.setDoOutput(true);

        byte[] out = compress(message).getBytes(StandardCharsets.ISO_8859_1);
        int length = out.length;

        http.setFixedLengthStreamingMode(length);
        http.setRequestProperty("Content-Type", "application/x-protobuf");
        if (tenant != null && tenant.length() > 0) {
            http.setRequestProperty("X-Scope-OrgID", tenant);
            http.setRequestProperty("tenant", tenant);
        }
        http.connect();
        try(OutputStream os = http.getOutputStream()) {
            os.write(out);
        }
        try(InputStream is = http.getInputStream()) {
            ret = new BufferedReader(
                    new InputStreamReader(is, StandardCharsets.UTF_8))
                    .lines()
                    .collect(Collectors.joining("\n"));
        }
        http.disconnect();

        return ret;
    }

}