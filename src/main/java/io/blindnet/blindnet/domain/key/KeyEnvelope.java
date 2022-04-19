package io.blindnet.blindnet.domain.key;

import org.json.JSONObject;

import java.io.Serializable;

/**
 * A wrapper class for a key envelope.
 */
public final class KeyEnvelope implements Serializable {

    /**
     * An id of the envelope.
     */
    private final String envelopeID;

    /**
     * A version of the envelope.
     */
    private final String envelopeVersion;

    /**
     * A key which is enveloped.
     */
    private final String encryptedSymmetricKey;

    /**
     * An id of the owner.
     */
    private final String keyOwnerID;

    /**
     * An id of the recipient.
     */
    private final String recipientID;

    /**
     * An id of the sender.
     */
    private final String senderID;

    /**
     * A timestamp of the envelope.
     */
    private final String timestamp;

    /**
     * A cryptographic signature of the envelop.
     */
    private String envelopeSignature;

    private KeyEnvelope(Builder builder) {
        envelopeID = builder.envelopeID;
        envelopeVersion = builder.envelopeVersion;
        encryptedSymmetricKey = builder.encryptedSymmetricKey;
        keyOwnerID = builder.keyOwnerID;
        senderID = builder.senderID;
        recipientID = builder.recipientID;
        timestamp = builder.timestamp;
        envelopeSignature = builder.keyEnvelopeSignature;
    }

    /**
     * Builder pattern implementation.
     */
    public static class Builder {

        private final String envelopeID;
        private String envelopeVersion;
        private String encryptedSymmetricKey;
        private String keyOwnerID;
        private String recipientID;
        private String senderID;
        private String timestamp;
        private String keyEnvelopeSignature;

        public Builder(String envelopeID) {
            this.envelopeID = envelopeID;
        }

        public Builder withVersion(String envelopeVersion) {
            this.envelopeVersion = envelopeVersion;
            return this;
        }

        public Builder withEncryptedSymmetricKey(String encryptedSymmetricKey) {
            this.encryptedSymmetricKey = encryptedSymmetricKey;
            return this;
        }

        public Builder withKeyOwnerID(String keyOwnerID) {
            this.keyOwnerID = keyOwnerID;
            return this;
        }

        public Builder withRecipientID(String recipientID) {
            this.recipientID = recipientID;
            return this;
        }

        public Builder withSenderID(String senderID) {
            this.senderID = senderID;
            return this;
        }

        public Builder withEnvelopeSignature(String keyEnvelopeSignature) {
            this.keyEnvelopeSignature = keyEnvelopeSignature;
            return this;
        }

        public Builder timestamp(String timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public KeyEnvelope build() {
            return new KeyEnvelope(this);
        }
    }

    public JSONObject toJSON() {
        return new JSONObject().put("envelopeID", envelopeID)
                .put("envelopeVersion", envelopeVersion)
                .put("encryptedSymmetricKey", encryptedSymmetricKey)
                .put("keyOwnerID", keyOwnerID)
                .put("recipientID", recipientID)
                .put("senderID", senderID)
                .put("timestamp", timestamp);
    }

    public void setEnvelopeSignature(String signature) {
        this.envelopeSignature = signature;
    }

    public String getEnvelopeID() {
        return envelopeID;
    }

    public String getEnvelopeVersion() {
        return envelopeVersion;
    }

    public String getEncryptedSymmetricKey() {
        return encryptedSymmetricKey;
    }

    public String getKeyOwnerID() {
        return keyOwnerID;
    }

    public String getRecipientID() {
        return recipientID;
    }

    public String getSenderID() {
        return senderID;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getEnvelopeSignature() {
        return envelopeSignature;
    }

}
