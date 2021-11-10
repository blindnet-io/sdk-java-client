package io.blindnet.blindnet.domain;

import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.util.Map;

/**
 * A wrapper object of the message represented as byte array and message data.
 */
public final class MessageArrayWrapper implements MessageWrapper {

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

    public static MessageArrayWrapper process(ByteBuffer wrapper) {
        /*
         * 1. reads a length of message metadata
         * 2. based on step 1 reads message metadata
         * 3. reads a message data which is what is left in the input
         */
        byte[] metadataLengthBA = new byte[4];
        wrapper.get(metadataLengthBA);
        int metadataLength = ByteBuffer.wrap(metadataLengthBA).getInt();

        byte[] metadata = new byte[metadataLength];
        wrapper.get(metadata);

        byte[] data = new byte[wrapper.remaining()];
        wrapper.get(data);

        return new MessageArrayWrapper(new JSONObject(new String(metadata)).toMap(), data);
    }

    public byte[] prepare() {
        byte[] metadataBA = new JSONObject(metadata).toString().getBytes();
        byte[] metadataLengthBA = ByteBuffer.allocate(4).putInt(metadataBA.length).array();

        /*
         * Creates data array of:
         * 1. a length of message metadata
         * 2. a message metadata
         * 3. a message data
         */
        return ByteBuffer.allocate(metadataLengthBA.length +
                metadataBA.length +
                data.length)
                .put(metadataLengthBA)
                .put(metadataBA)
                .put(data)
                .array();
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public byte[] getData() {
        return data;
    }

}
