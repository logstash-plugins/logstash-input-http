package org.logstash.plugins.inputs.http.util;

import org.logstash.plugins.inputs.http.IMessageHandler;

import java.util.Map;

/**
 * An implementation of {@link IMessageHandler} that wraps another {@link IMessageHandler} with an
 * {@link ExecutionObserver}, ensuring that the delegate's {@link IMessageHandler#onNewMessage} is
 * observed.
 */
public class ExecutionObservingMessageHandler implements IMessageHandler {
    private final ExecutionObserver executionObserver;
    private final IMessageHandler delegate;

    public ExecutionObservingMessageHandler(final ExecutionObserver executionObserver,
                                            final IMessageHandler delegate) {
        this.executionObserver = executionObserver;
        this.delegate = delegate;
    }

    @Override
    public boolean onNewMessage(final String remoteAddress,
                                final Map<String, String> headers,
                                final String body) {
        return executionObserver.observeExecution(() -> delegate.onNewMessage(remoteAddress, headers, body));
    }

    @Override
    public boolean validatesToken(final String token) {
        return delegate.validatesToken(token);
    }

    @Override
    public boolean requiresToken() {
        return delegate.requiresToken();
    }

    @Override
    public IMessageHandler copy() {
        return new ExecutionObservingMessageHandler(this.executionObserver, delegate.copy());
    }

    @Override
    public Map<String, String> responseHeaders() {
        return delegate.responseHeaders();
    }
}
