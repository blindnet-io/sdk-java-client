package io.blindnet.blindnet.domain.message;

/**
 * A wrapper class for the result of sending the Signal message.
 */
public class SignalSendMessageResult {

    /**
     * Indicates whether the message is sent successfully.
     */
    private final boolean isSuccessful;

    /**
     * A message representing the response message of Blindnet API.
     */
    private final String message;

    public SignalSendMessageResult(boolean isSuccessful, String message) {
        this.isSuccessful = isSuccessful;
        this.message = message;
    }

    public boolean isSuccessful() {
        return isSuccessful;
    }

    public String getMessage() {
        return message;
    }

}
