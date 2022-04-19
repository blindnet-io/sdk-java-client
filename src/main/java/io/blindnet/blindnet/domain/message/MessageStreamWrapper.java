package io.blindnet.blindnet.domain.message;

import java.io.InputStream;
import java.util.Map;

/**
 * A wrapper class of the message represented as input stream and message metadata.
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
