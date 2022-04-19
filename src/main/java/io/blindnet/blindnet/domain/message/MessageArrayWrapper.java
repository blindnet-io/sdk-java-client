package io.blindnet.blindnet.domain.message;

import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.util.Map;

/**
 * A wrapper class of the message represented as byte array and message metadata.
 */
public final class MessageArrayWrapper implements MessageWrapper {

    /**
     * The ID of signal message sender.
     */
    private String signalSenderID;

    /**
     * The ID of signal sender's device.
     */
    private String signalSenderDeviceID;

    /**
     * The time signal message was sent at.
     */
    private String signalMessageTimeSent;
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

    public void setSignalSenderID(String signalSenderID) {
        this.signalSenderID = signalSenderID;
    }

    public void setSignalSenderDeviceID(String signalSenderDeviceID) {
        this.signalSenderDeviceID = signalSenderDeviceID;
    }

    public void setSignalMessageTimeSent(String signalMessageTimeSent) {
        this.signalMessageTimeSent = signalMessageTimeSent;
    }

    public String getSignalSenderID() {
        return signalSenderID;
    }

    public String getSignalSenderDeviceID() {
        return signalSenderDeviceID;
    }

    public String getSignalMessageTimeSent() {
        return signalMessageTimeSent;
    }

}
