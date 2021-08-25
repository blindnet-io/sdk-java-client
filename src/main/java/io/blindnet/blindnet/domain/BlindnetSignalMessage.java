package io.blindnet.blindnet.domain;

import org.json.JSONObject;

// todo javadoc
public class BlindnetSignalMessage {

    private final int id;
    private final String senderID;
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
                    responseBody.isNull("senderID") ? responseBody.getString("senderID"): null,
                    responseBody.isNull("recipientID") ? responseBody.getString("recipientID"): null,
                    responseBody.isNull("recipientDeviceID") ? responseBody.getString("recipientDeviceID"): null,
                    responseBody.isNull("protocolVersion") ? responseBody.getString("protocolVersion"): null,
                    responseBody.isNull("messageContent") ? responseBody.getString("messageContent"): null,
                    responseBody.isNull("dhKey") ? responseBody.getString("dhKey"): null,
                    responseBody.getString("timeSent"),
                    responseBody.isNull("timeDelivered") ? responseBody.getString("timeDelivered"): null,
                    responseBody.isNull("timeRead") ? responseBody.getString("timeRead"): null,
                    new BlindnetSignalMessageSenderKeys(responseBody.getInt("id"),
                            responseBody.isNull("publicIk") ? responseBody.getString("publicIk"): null,
                            responseBody.isNull("publicEk") ? responseBody.getString("publicEk"): null,
                            responseBody.getInt("messageID")),
                    responseBody.isNull("senderApplicationID") ? responseBody.getString("senderApplicationID"): null,
                    responseBody.isNull("recipientApplicationID") ? responseBody.getString("recipientApplicationID"): null);
    }

    public int getId() {
        return id;
    }

    public String getSenderID() {
        return senderID;
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
