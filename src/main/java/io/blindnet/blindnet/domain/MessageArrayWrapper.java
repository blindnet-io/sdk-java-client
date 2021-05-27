package io.blindnet.blindnet.domain;

import java.util.Map;

/**
 * A wrapper object of the message represented as byte array and message data.
 */
public final class MessageArrayWrapper {

    /**
     * A metadata of the message.
     */
    private Map<String, Object> metadata;

    /**
     * A data of the message.
     */
    private final byte[] data;

    public MessageArrayWrapper(Map<String, Object> metadata, byte[] data) {
        this.metadata = metadata;
        this.data = data;
    }

    public MessageArrayWrapper(byte[] data) {
        this.data = data;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public byte[] getData() {
        return data;
    }

}
