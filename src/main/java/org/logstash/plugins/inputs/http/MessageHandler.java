package org.logstash.plugins.inputs.http;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;

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
     * @param headers
     * @param body
     */
    public boolean onNewMessage(String remoteAddress, Map<String,String> headers, byte[] body) {
        logger.debug("onNewMessage");
        return false;
    }

    public MessageHandler copy() {
        logger.debug("copy");
        return new MessageHandler();
    }

    public boolean validatesToken(String token) {
        logger.debug("validatesToken");
        return false;
    }

    public Map<String, String> responseHeaders() {
        logger.debug("responseHeaders");
        return null;
    }

    public boolean requiresToken() { return false; }
}
