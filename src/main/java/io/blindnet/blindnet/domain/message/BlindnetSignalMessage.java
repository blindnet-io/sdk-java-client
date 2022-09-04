package io.blindnet.blindnet.domain.message;

import org.json.JSONObject;

/**
 * A wrapper class for Signal message sent/received to/from Blindnet server.
 */
public class BlindnetSignalMessage {

    /**
     * The ID of the message.
     */
    private final int id;

    /**
     * The ID of sender.
     */
    private final String senderID;

    /**
     * The ID of sender's device.
     */
    private final String senderDeviceID;

    /**
     * The ID of recipient.
     */
    private final String recipientID;

    /**
     * The ID of recipient's device.
     */
    private final String recipientDeviceID;

    /**
     * The version of the message protocol.
     */
    private final String protocolVersion;

    /**
     * The content of the message.
     */
    private final String messageContent;

    /**
     * Diffie-Hellman key.
     */
    private final String dhKey;

    /**
     * The time message was sent at.
     */
    private final String timeSent;

    /**
     * The time message was delivered at.
     */
    private final String timeDelivered;

    /**
     * The time message was read at.
     */
    private final String timeRead;

    /**
     * The wrapper for the sender public keys.
     */
    private final BlindnetSignalMessageSenderKeys blindnetSignalMessageSenderKeys;

    /**
     * The ID of the sender's application.
     */
    private final String senderApplicationID;

    /**
     * The ID of the recipient's application.
     */
    private final String recipientApplicationID;

    public BlindnetSignalMessage(int id,
                                 String senderID,
                                 String senderDeviceID,
                                 String recipientID,
                                 String recipientDeviceID,
                                 String protocolVersion,
                                 String messageContent,
                                 String dhKey,
                                 String timeSent,
                                 String timeDelivered,
                                 String timeRead,
                                 BlindnetSignalMessageSenderKeys blindnetSignalMessageSenderKeys,
                                 String senderApplicationID,
                                 String recipientApplicationID) {

        this.id = id;
        this.senderID = senderID;
        this.senderDeviceID = senderDeviceID;
        this.recipientID = recipientID;
        this.recipientDeviceID = recipientDeviceID;
        this.protocolVersion = protocolVersion;
        this.messageContent = messageContent;
        this.dhKey = dhKey;
        this.timeSent = timeSent;
        this.timeDelivered = timeDelivered;
        this.timeRead = timeRead;
        this.blindnetSignalMessageSenderKeys = blindnetSignalMessageSenderKeys;
        this.senderApplicationID = senderApplicationID;
        this.recipientApplicationID = recipientApplicationID;
    }

    public static BlindnetSignalMessage create(JSONObject responseBody) {
        return new BlindnetSignalMessage(responseBody.getInt("id"),
                getValueAsString(responseBody, "senderID"),
                getValueAsString(responseBody, "senderDeviceID"),
                getValueAsString(responseBody, "recipientID"),
                getValueAsString(responseBody, "recipientDeviceID"),
                getValueAsString(responseBody, "protocolVersion"),
                getValueAsString(responseBody, "messageContent"),
                getValueAsString(responseBody, "dhKey"),
                getValueAsString(responseBody, "timeSent"),
                getValueAsString(responseBody, "timeDelivered"),
                getValueAsString(responseBody, "timeRead"),
                new BlindnetSignalMessageSenderKeys(responseBody.getJSONObject("blindnetSignalMessageSenderKeys").getInt("id"),
                        getValueAsString(responseBody.getJSONObject("blindnetSignalMessageSenderKeys"), "publicIk"),
                        getValueAsString(responseBody.getJSONObject("blindnetSignalMessageSenderKeys"), "publicEk"),
                        getValueAsInt(responseBody.getJSONObject("blindnetSignalMessageSenderKeys"), "messageID")),
                getValueAsString(responseBody, "senderApplicationID"),
                getValueAsString(responseBody, "recipientApplicationID"));
    }

    public int getId() {
        return id;
    }

    public String getSenderID() {
        return senderID;
    }

    public String getSenderDeviceID() {
        return senderDeviceID;
    }

    public String getRecipientID() {
        return recipientID;
    }

    public String getRecipientDeviceID() {
        return recipientDeviceID;
    }

    public String getProtocolVersion() {
        return protocolVersion;
    }

    public String getMessageContent() {
        return messageContent;
    }

    public String getDhKey() {
        return dhKey;
    }

    public String getTimeSent() {
        return timeSent;
    }

    public String getTimeDelivered() {
        return timeDelivered;
    }

    public String getTimeRead() {
        return timeRead;
    }

    public BlindnetSignalMessageSenderKeys getSignalMessageSenderKeys() {
        return blindnetSignalMessageSenderKeys;
    }

    public String getSenderApplicationID() {
        return senderApplicationID;
    }

    public String getRecipientApplicationID() {
        return recipientApplicationID;
    }

    private static String getValueAsString(JSONObject body, String key) {
        if (!body.has(key)) {
            return null;
        }
        Object object = body.get(key);
        if (object instanceof String) {
            return (String) object;
        }
        return null;
    }

    private static int getValueAsInt(JSONObject body, String key) {
        if (!body.has(key)) {
            return -1;
        }
        Object object = body.get(key);
        if (object instanceof Integer) {
            return (Integer) object;
        }
        return -1;
    }

}
