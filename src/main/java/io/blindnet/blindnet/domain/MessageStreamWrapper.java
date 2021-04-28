package io.blindnet.blindnet.domain;

import java.io.InputStream;

public class MessageStreamWrapper {

    private final byte[] metadata;
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
