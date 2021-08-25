package io.blindnet.blindnet.domain;

// todo javadoc
public class BlindnetSignalMessageSenderKeys {

    private final int id;
    private final String publicIk;
    private final String publicEk;
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
