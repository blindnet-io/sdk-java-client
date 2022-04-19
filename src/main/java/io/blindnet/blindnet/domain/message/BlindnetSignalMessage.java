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
        // todo refactor
        return new BlindnetSignalMessage(responseBody.getInt("id"),
                    responseBody.isNull("senderID") ? null: responseBody.getString("senderID"),
                    responseBody.isNull("senderDeviceID") ? null: responseBody.getString("senderDeviceID"),
                    responseBody.isNull("recipientID") ? null: responseBody.getString("recipientID"),
                    !responseBody.has("recipientDeviceID") || responseBody.isNull("recipientDeviceID") ? null: responseBody.getString("recipientDeviceID"),
                    responseBody.isNull("protocolVersion") ? null: responseBody.getString("protocolVersion"),
                    responseBody.isNull("messageContent") ? null: responseBody.getString("messageContent"),
                    responseBody.isNull("dhKey") ? null: responseBody.getString("dhKey"),
                    responseBody.getString("timeSent"),
                    responseBody.isNull("timeDelivered") ? null: responseBody.getString("timeDelivered"),
                    !responseBody.has("timeRead") || responseBody.isNull("timeRead") ? null: responseBody.getString("timeRead"),
                    new BlindnetSignalMessageSenderKeys(responseBody.getJSONObject("blindnetSignalMessageSenderKeys").getInt("id"),
                            !responseBody.getJSONObject("blindnetSignalMessageSenderKeys").has("publicIk")
                                    || responseBody.getJSONObject("blindnetSignalMessageSenderKeys").isNull("publicIk") ? null: responseBody.getJSONObject("blindnetSignalMessageSenderKeys").getString("publicIk"),
                            !responseBody.getJSONObject("blindnetSignalMessageSenderKeys").has("publicEk")
                                    || responseBody.getJSONObject("blindnetSignalMessageSenderKeys").isNull("publicEk") ? null: responseBody.getJSONObject("blindnetSignalMessageSenderKeys").getString("publicEk"),
                            !responseBody.getJSONObject("blindnetSignalMessageSenderKeys").has("messageID")
                                    || responseBody.getJSONObject("blindnetSignalMessageSenderKeys").isNull("messageID") ? -1: responseBody.getJSONObject("blindnetSignalMessageSenderKeys").getInt("messageID")),
                    responseBody.isNull("senderApplicationID") ? null: responseBody.getString("senderApplicationID"),
                    responseBody.isNull("recipientApplicationID") ? null: responseBody.getString("recipientApplicationID"));
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

}
