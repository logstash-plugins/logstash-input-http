package org.logstash.plugins.inputs.http.util;

import java.nio.file.Path;
import java.nio.file.Paths;

abstract class TestUtils {

    private static final Path RESOURCES = Paths.get("src/test/resources");

    private TestUtils() {
    }

    static Path resource(String name) {
        return RESOURCES.resolve(name);
    }

    static String resourcePath(String name) {
        return resource(name).toString();
    }
}
