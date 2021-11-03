package io.blindnet.blindnet.domain;

import org.json.JSONObject;

// todo javadoc
public class BlindnetSignalMessage {

    private final int id;
    private final String senderID;
    private final String senderDeviceID;
    private final String recipientID;
    private final String recipientDeviceID;
    private final String protocolVersion;
    private final String messageContent;
    private final String dhKey;
    private final String timeSent;
    private final String timeDelivered;
    private final String timeRead;
    private final BlindnetSignalMessageSenderKeys blindnetSignalMessageSenderKeys;
    private final String senderApplicationID;
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
                    // todo recipientDeviceID missing in response
                    !responseBody.has("recipientDeviceID") || responseBody.isNull("recipientDeviceID") ? null: responseBody.getString("recipientDeviceID"),
                    responseBody.isNull("protocolVersion") ? null: responseBody.getString("protocolVersion"),
                    responseBody.isNull("messageContent") ? null: responseBody.getString("messageContent"),
                    responseBody.isNull("dhKey") ? null: responseBody.getString("dhKey"),
                    responseBody.getString("timeSent"),
                    responseBody.isNull("timeDelivered") ? null: responseBody.getString("timeDelivered"),
                    // todo timeRead missing in response
                    !responseBody.has("timeRead") || responseBody.isNull("timeRead") ? null: responseBody.getString("timeRead"),
                    new BlindnetSignalMessageSenderKeys(responseBody.getInt("id"),
                            // todo publicIk missing in response
                            !responseBody.has("publicIk") || responseBody.isNull("publicIk") ? null: responseBody.getString("publicIk"),
                            // todo publicEk missing in response
                            !responseBody.has("publicEk") || responseBody.isNull("publicEk") ? null: responseBody.getString("publicEk"),
                            !responseBody.has("messageID") || responseBody.isNull("messageID") ? -1: responseBody.getInt("messageID")),
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
