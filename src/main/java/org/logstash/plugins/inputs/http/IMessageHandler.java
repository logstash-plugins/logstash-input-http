package org.logstash.plugins.inputs.http;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;

/**
 * Created by joaoduarte on 16/10/2017.
 */
public interface IMessageHandler {
    /**
     * This is triggered on every new message parsed by the http handler
     * and should be executed in the ruby world.
     *
     * @param remoteAddress
     * @param message
     */
    FullHttpResponse onNewMessage(String remoteAddress, FullHttpRequest message);

    /**
     *
     * @return copy of the message handler
     */
    IMessageHandler copy();
}
