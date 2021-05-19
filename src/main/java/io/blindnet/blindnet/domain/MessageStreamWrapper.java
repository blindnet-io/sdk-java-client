package io.blindnet.blindnet.domain;

import java.io.InputStream;

/**
 * A wrapper object of the message represented as input stream and message data.
 */
public final class MessageStreamWrapper {

    /**
     * A metadata of the message.
     */
    private final byte[] metadata;

    /**
     * A data of the message.
     */
    private final InputStream data;

    public MessageStreamWrapper(byte[] metadata, InputStream data) {
        this.metadata = metadata;
        this.data = data;
    }

    public byte[] getMetadata() {
        return metadata;
    }

    public InputStream getData() {
        return data;
    }

}
