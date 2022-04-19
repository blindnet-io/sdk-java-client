package io.blindnet.blindnet.domain.message;

/**
 * A wrapper class for sender's public keys sent as part of Signal message.
 */
public class BlindnetSignalMessageSenderKeys {

    /**
     * The ID of the key pair.
     */
    private final int id;

    /**
     * The public identity key.
     */
    private final String publicIk;

    /**
     * The public ephemeral key.
     */
    private final String publicEk;

    /**
     * The ID of the message.
     */
    private final int messageID;

    public BlindnetSignalMessageSenderKeys(int id, String publicIk, String publicEk, int messageID) {
        this.id = id;
        this.publicIk = publicIk;
        this.publicEk = publicEk;
        this.messageID = messageID;
    }

    public int getId() {
        return id;
    }

    public String getPublicIk() {
        return publicIk;
    }

    public String getPublicEk() {
        return publicEk;
    }

    public int getMessageID() {
        return messageID;
    }

}
