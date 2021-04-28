package io.blindnet.blindnet.domain;

public class MessageArrayWrapper {

    private final byte[] metadata;
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
