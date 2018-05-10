package org.logstash.plugins.inputs.http;

import java.util.Map;

/**
 * Created by joaoduarte on 16/10/2017.
 */
public interface IMessageHandler {
    /**
     * This is triggered on every new message parsed by the http handler
     * and should be executed in the ruby world.
     *
     * @param remoteAddress
     * @param headers
     * @param body
     */
    boolean onNewMessage(String remoteAddress, Map<String,String> headers, String body);

    /**
     *
     * @param token
     * @return
     */
    boolean validatesToken(String token);

    /**
     *
     * @return copy of the message handler
     */
    IMessageHandler copy();

    /**
     *
     * @return
     */
    Map<String, String> responseHeaders();
}
