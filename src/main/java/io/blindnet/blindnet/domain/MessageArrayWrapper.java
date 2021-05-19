package io.blindnet.blindnet.domain;

/**
 * A wrapper object of the message represented as byte array and message data.
 */
public final class MessageArrayWrapper {

    /**
     * A metadata of the message.
     */
    private final byte[] metadata;

    /**
     * A data of the message.
     */
    private final byte[] data;

    public MessageArrayWrapper(byte[] metadata, byte[] data) {
        this.metadata = metadata;
        this.data = data;
    }

    public byte[] getMetadata() {
        return metadata;
    }

    public byte[] getData() {
        return data;
    }

}
