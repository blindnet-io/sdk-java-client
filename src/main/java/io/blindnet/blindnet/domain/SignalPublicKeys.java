package io.blindnet.blindnet.domain;

import java.security.PublicKey;

/**
 *
 */
public class SignalPublicKeys {

    private final String deviceID;
    private final PublicKey publicIdentityKey;
    private final PublicKey publicPreKey;
    private final String preKeyPairID;
    private final PublicKey publicOneTimePrKey;
    private final String oneTimePreKeyID;

    public SignalPublicKeys(String deviceID,
                            PublicKey publicIdentityKey,
                            PublicKey publicPreKey,
                            String preKeyPairID,
                            PublicKey publicOneTimePrKey,
                            String oneTimePreKeyID) {

        this.deviceID = deviceID;
        this.publicIdentityKey = publicIdentityKey;
        this.publicPreKey = publicPreKey;
        this.preKeyPairID = preKeyPairID;
        this.publicOneTimePrKey = publicOneTimePrKey;
        this.oneTimePreKeyID = oneTimePreKeyID;
    }

    public String getDeviceID() {
        return deviceID;
    }

    public PublicKey getPublicIdentityKey() {
        return publicIdentityKey;
    }

    public PublicKey getPublicPreKey() {
        return publicPreKey;
    }

    public String getPreKeyPairID() {
        return preKeyPairID;
    }

    public PublicKey getPublicOneTimePrKey() {
        return publicOneTimePrKey;
    }

    public String getOneTimePreKeyID() {
        return oneTimePreKeyID;
    }

}
