package io.blindnet.blindnet.domain;

import org.json.JSONObject;

/**
 * A wrapper class for signal device data.
 */
public class SignalDevice {

    /**
     * The ID of the device.
     */
    private final String deviceId;

    /**
     * The ID of the user.
     */
    private final String userId;

    public SignalDevice(String userId, String deviceId) {
        this.userId = userId;
        this.deviceId = deviceId;
    }

    public static SignalDevice create(final JSONObject responseBody) {
        return new SignalDevice(responseBody.getString("userID"), responseBody.getString("deviceID"));
    }

    public String getUserId() {
        return userId;
    }

    public String getDeviceId() {
        return deviceId;
    }

}
