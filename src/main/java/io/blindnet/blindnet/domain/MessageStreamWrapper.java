package io.blindnet.blindnet.domain;

import java.io.InputStream;
import java.util.Map;

/**
 * A wrapper object of the message represented as input stream and message data.
 */
public final class MessageStreamWrapper implements MessageWrapper {

    /**
     * A metadata of the message.
     */
    private Map<String, Object> metadata;

    /**
     * A data of the message.
     */
    private final InputStream data;

    public MessageStreamWrapper(Map<String, Object> metadata, InputStream data) {
        this.metadata = metadata;
        this.data = data;
    }

    public MessageStreamWrapper(InputStream data) {
        this.data = data;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public InputStream getData() {
        return data;
    }

}
