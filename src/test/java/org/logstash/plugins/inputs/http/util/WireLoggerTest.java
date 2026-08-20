package org.logstash.plugins.inputs.http.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.test.appender.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.logstash.plugins.inputs.http.IMessageHandler;
import org.logstash.plugins.inputs.http.NettyHttpServer;

import org.awaitility.Awaitility;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.util.concurrent.TimeUnit;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.*;

class WireLoggerTest {

    private static final String CONFIG = "log4j2-test-wirelogger.xml";

    private static final String HOST = "127.0.0.1";

    private NettyHttpServer server;
    private int port;
    private URI originalConfigUri;
    private ListAppender logSpy;

    @BeforeEach
    void setUp() throws Exception {
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        originalConfigUri = ctx.getConfigLocation();
        ctx.setConfigLocation(getClass().getClassLoader().getResource(CONFIG).toURI());

        port = findFreePort();

        IMessageHandler noopHandler = new IMessageHandler() {
            @Override
            public boolean onNewMessage(String remoteAddress, Map<String, String> headers, String body) {
                return true;
            }

            @Override
            public boolean validatesToken(String token) {
                return true;
            }

            @Override
            public boolean requiresToken() {
                return false;
            }

            @Override
            public IMessageHandler copy() {
                return this;
            }

            @Override
            public Map<String, String> responseHeaders() {
                return Collections.emptyMap();
            }
        };

        server = new NettyHttpServer("test", HOST, port, noopHandler, null, 2, 100, 1024 * 1024, 200);
        Thread serverThread = new Thread(server);
        serverThread.setDaemon(true);
        serverThread.setName("Test - NettyHttpServer runner");
        serverThread.start();
        waitForServerReady();

        logSpy = getListAppender("WireLoggerList");
        logSpy.clear();
    }

    @AfterEach
    void tearDown() throws Exception {
        server.close();
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        ctx.setConfigLocation(originalConfigUri);
    }

    @Test
    void wireLoggerLogsOpeningAndClosingConnectionAroundHttpRequest() throws Exception {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("http://" + HOST + ":" + port + "/"))
                    .POST(HttpRequest.BodyPublishers.ofString("{\"message\": \"hello\"}"))
                    .header("Content-Type", "application/json")
                    .build();

            client.send(request, HttpResponse.BodyHandlers.ofString());
        }
        // Implicit close of auto-closeable client so that "Closing connection" is logged before we assert.

        List<String> messages = logSpy.getMessages();
        Awaitility.await()
                .atMost(5, TimeUnit.SECONDS)
                .until(() -> messages.size() >= 4);
        
        assertThat(messages, hasItem(matchesPattern("Opening connection .*" + HOST + ":\\d+")));
        assertThat(messages, hasItem(matchesPattern("Closing connection .*" + HOST + ":\\d+")));
    }

    @Test
    void wireLoggerDumpsRawHttpRequestContent() throws Exception {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("http://" + HOST + ":" + port + "/"))
                    .POST(HttpRequest.BodyPublishers.ofString("{\"message\": \"hello\"}"))
                    .header("Content-Type", "application/json")
                    .build();

            client.send(request, HttpResponse.BodyHandlers.ofString());
        }

        List<String> messages = logSpy.getMessages();
        assertThat(messages, hasItem(matchesPattern("<< .*" + HOST + ":\\d+ : POST.*")));
        assertThat(messages, hasItem(containsString("[\\r][\\n]")));
        assertThat(messages, hasItem(containsString("{\"message\": \"hello\"}")));
    }

    @Test
    void wireLoggerDumpsRawHttpResponseContent() throws Exception {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("http://" + HOST + ":" + port + "/"))
                    .POST(HttpRequest.BodyPublishers.ofString("{\"message\": \"hello\"}"))
                    .header("Content-Type", "application/json")
                    .build();

            client.send(request, HttpResponse.BodyHandlers.ofString());
        }

        List<String> messages = logSpy.getMessages();
        assertThat(messages, hasItem(matchesPattern(">> .*" + HOST + ":\\d+ : HTTP/1\\.1 200 OK.*")));
        assertThat(messages, hasItem(containsString("[\\r][\\n]")));
    }

    @Test
    void wireLoggerTruncatesRequestBiggerThanMaxDumpLength() throws Exception {
        // Netty's AdaptiveRecvByteBufAllocator starts at 1024 bytes and jumps to 8192 after the
        // first full read. With a body of MAX_DUMP_LENGTH * 3 bytes the second read chunk is
        // 8192 > MAX_DUMP_LENGTH, which guarantees the truncation notice is appended.
        String largeBody = "A".repeat(WireLogger.MAX_DUMP_LENGTH * 3);

        try (HttpClient client = HttpClient.newHttpClient()) {
            client.send(HttpRequest.newBuilder()
                    .uri(URI.create("http://" + HOST + ":" + port + "/"))
                    .POST(HttpRequest.BodyPublishers.ofString(largeBody))
                    .header("Content-Type", "application/json")
                    .build(), HttpResponse.BodyHandlers.discarding());
        }

        assertThat(logSpy.getMessages(), hasItem(containsString("truncated, total")));
    }

    private static final String SIZE_PROP = "logstash.httpinput.wire.dump.size";

    @Test
    void readDumpSizePropertyReturnsTheConfiguredValueAsInteger() throws Exception {
        System.setProperty(SIZE_PROP, "2048");
        try {
            assertEquals(2048, WireLogger.readDumpSizeProperty());
        } finally {
            System.clearProperty(SIZE_PROP);
        }
    }

    @Test
    void validateDumpSizePropertyReturnsPositiveValue() throws Exception {
        System.setProperty(SIZE_PROP, "2048");
        try {
            assertDoesNotThrow(WireLogger::validateDumpSizeProperty);
        } finally {
            System.clearProperty(SIZE_PROP);
        }
    }

    @Test
    void validateDumpSizePropertyForUnlimitedValue() {
        System.setProperty(SIZE_PROP, "0");
        try {
            assertDoesNotThrow(WireLogger::validateDumpSizeProperty);
        } finally {
            System.clearProperty(SIZE_PROP);
        }
    }

    @Test
    void validateDumpSizePropertyThrowsForNegativeValue() {
        System.setProperty(SIZE_PROP, "-1");
        try {
            assertThrows(RuntimeException.class, WireLogger::validateDumpSizeProperty);
        } finally {
            System.clearProperty(SIZE_PROP);
        }
    }

    @Test
    void validateDumpSizePropertyThrowsForNonNumericValue() {
        System.setProperty(SIZE_PROP, "notanumber");
        try {
            assertThrows(RuntimeException.class, WireLogger::validateDumpSizeProperty);
        } finally {
            System.clearProperty(SIZE_PROP);
        }
    }

    private void waitForServerReady() {
        Awaitility.await()
                .atMost(5, TimeUnit.SECONDS)
                .until(this::checkServerReady);
    }

    private Boolean checkServerReady() {
        try (Socket ignored = new Socket(HOST, port)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static int findFreePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        }
    }

    private ListAppender getListAppender(String name) {
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        return (ListAppender) ctx.getConfiguration().getAppender(name);
    }
}
