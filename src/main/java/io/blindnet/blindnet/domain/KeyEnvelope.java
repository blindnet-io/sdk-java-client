package io.blindnet.blindnet.domain;

import java.io.Serializable;

public class KeyEnvelope implements Serializable {

    private final String envelopeId;
    private final String envelopeVersion;
    private final String key;
    private final String ownerId;
    private final String recipientId;
    private final String senderId;
    private final long timestamp;
    private String keyEnvelopeSignature;

    private KeyEnvelope(Builder builder) {
        envelopeId = builder.envelopeId;
        envelopeVersion = builder.envelopeVersion;
        key = builder.key;
        ownerId = builder.ownerId;
        senderId = builder.senderId;
        recipientId = builder.recipientId;
        timestamp = builder.timestamp;
        keyEnvelopeSignature = builder.keyEnvelopeSignature;
    }

    public static class Builder {

        private String envelopeId;
        private String envelopeVersion;
        private String key;
        private String ownerId;
        private String recipientId;
        private String senderId;
        private long timestamp;
        private String keyEnvelopeSignature;

        public Builder(String envelopeId) {
            this.envelopeId = envelopeId;
        }

        public Builder withVersion(String envelopeVersion){
            this.envelopeVersion = envelopeVersion;
            return this;
        }

        public Builder withKey(String key){
            this.key = key;
            return this;
        }

        public Builder withOwnerId(String ownerId){
            this.ownerId = ownerId;
            return this;
        }

        public Builder withRecipientId(String recipientId){
            this.recipientId = recipientId;
            return this;
        }

        public Builder withSenderId(String senderId) {
            this.senderId = senderId;
            return this;
        }

        public Builder withEnvelopeSignature(String keyEnvelopeSignature) {
            this.keyEnvelopeSignature = keyEnvelopeSignature;
            return this;
        }

        public Builder timestamp(long timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public KeyEnvelope build(){
            return new KeyEnvelope(this);
        }
    }

    public void setKeyEnvelopeSignature(String signature) {
        this.keyEnvelopeSignature = signature;
    }

    public String getEnvelopeId() {
        return envelopeId;
    }

    public String getEnvelopeVersion() {
        return envelopeVersion;
    }

    public String getKey() {
        return key;
    }

    public String getOwnerId() {
        return ownerId;
    }

    public String getRecipientId() {
        return recipientId;
    }

    public String getSenderId() {
        return senderId;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getKeyEnvelopeSignature() {
        return keyEnvelopeSignature;
    }

}
