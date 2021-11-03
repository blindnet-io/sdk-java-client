package io.blindnet.blindnet.domain;

import org.json.JSONObject;

public class SignalDeviceIds {

    private final String userId;
    private final String deviceId;

    public SignalDeviceIds(String userId, String deviceId) {
        this.userId = userId;
        this.deviceId = deviceId;
    }

    public static SignalDeviceIds create(JSONObject responseBody) {
        return new SignalDeviceIds(responseBody.getString("userID"), responseBody.getString("deviceID"));
    }

    public String getUserId() {
        return userId;
    }

    public String getDeviceId() {
        return deviceId;
    }
}
