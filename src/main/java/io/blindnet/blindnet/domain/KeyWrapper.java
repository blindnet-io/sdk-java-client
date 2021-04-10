package io.blindnet.blindnet.domain;

//todo; FR-SDK05
public class KeyWrapper {

    private String key;
    private String signature;
    private int ownerId;
    private int senderId;
    private int recipientId;

    public KeyWrapper(String key, String signature, int ownerId, int senderId, int recipientId) {
        this.key = key;
        this.signature = signature;
        this.ownerId = ownerId;
        this.senderId = senderId;
        this.recipientId = recipientId;
    }

    public String getKey() {
        return key;
    }

    public String getSignature() {
        return signature;
    }

    public int getOwnerId() {
        return ownerId;
    }

    public int getSenderId() {
        return senderId;
    }

    public int getRecipientId() {
        return recipientId;
    }

}
