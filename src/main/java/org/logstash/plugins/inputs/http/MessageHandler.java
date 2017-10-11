package org.logstash.plugins.inputs.http;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This class is implemented in ruby in `lib/logstash/inputs/http/message_listener`,
 * this class is used to link the events triggered from the different connection to the actual
 * work inside the plugin.
 */
// This need to be implemented in Ruby
public class MessageHandler implements IMessageHandler {
    private final static Logger logger = LogManager.getLogger(MessageHandler.class);

    /**
     * This is triggered on every new message parsed by the http handler
     * and should be executed in the ruby world.
     *
     * @param remoteAddress
     * @param message
     */
    public FullHttpResponse onNewMessage(String remoteAddress, FullHttpRequest message) {
        logger.debug("onNewMessage");
        return null;
    }

    public MessageHandler copy() {
        logger.debug("copy");
        return new MessageHandler();
    }
}
