package io.blindnet.blindnet.domain;

import java.io.Serializable;

/**
 * A wrapper object for key envelope.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public final class KeyEnvelope implements Serializable {

    /**
     * An id of the envelope.
     */
    private final String envelopeId;

    /**
     * A version of the envelope.
     */
    private final String envelopeVersion;

    /**
     * A key which is enveloped.
     */
    private final String key;

    /**
     * An id of the owner.
     */
    private final String ownerId;

    /**
     * An id of the recipient.
     */
    private final String recipientId;

    /**
     * An id of the sender.
     */
    private final String senderId;

    /**
     * A timestamp of the envelope.
     */
    private final long timestamp;

    /**
     * A cryptographic signature of the envelop.
     */
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

    /**
     * Builder pattern implementation.
     */
    public static class Builder {

        private final String envelopeId;
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

        public Builder withVersion(String envelopeVersion) {
            this.envelopeVersion = envelopeVersion;
            return this;
        }

        public Builder withKey(String key) {
            this.key = key;
            return this;
        }

        public Builder withOwnerId(String ownerId) {
            this.ownerId = ownerId;
            return this;
        }

        public Builder withRecipientId(String recipientId) {
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

        public KeyEnvelope build() {
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
