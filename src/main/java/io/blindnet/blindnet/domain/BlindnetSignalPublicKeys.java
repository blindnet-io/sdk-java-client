package io.blindnet.blindnet.domain;

import org.whispersystems.libsignal.ecc.ECPublicKey;

// todo javadoc
public class BlindnetSignalPublicKeys {

    private final String userID;
    private final String deviceID;
    private final String identityID;
    private final ECPublicKey publicIdentityKey;
    private final String preKeyPairID;
    private final ECPublicKey publicPreKey;
    private final byte[] preKeySignature;
    private final String oneTimePreKeyID;
    private final ECPublicKey publicOneTimePrKey;


    public BlindnetSignalPublicKeys(String userID,
                                    String deviceID,
                                    String identityID,
                                    ECPublicKey publicIdentityKey,
                                    String preKeyPairID,
                                    ECPublicKey publicPreKey,
                                    byte[] preKeySignature,
                                    String oneTimePreKeyID,
                                    ECPublicKey publicOneTimePrKey) {

        this.userID = userID;
        this.deviceID = deviceID;
        this.identityID = identityID;
        this.publicIdentityKey = publicIdentityKey;
        this.preKeyPairID = preKeyPairID;
        this.publicPreKey = publicPreKey;
        this.preKeySignature = preKeySignature;
        this.oneTimePreKeyID = oneTimePreKeyID;
        this.publicOneTimePrKey = publicOneTimePrKey;
    }

    public String getUserID() {
        return userID;
    }

    public String getIdentityID() {
        return identityID;
    }

    public byte[] getPreKeySignature() {
        return preKeySignature;
    }

    public String getDeviceID() {
        return deviceID;
    }

    public ECPublicKey getPublicIdentityKey() {
        return publicIdentityKey;
    }

    public ECPublicKey getPublicPreKey() {
        return publicPreKey;
    }

    public String getPreKeyPairID() {
        return preKeyPairID;
    }

    public ECPublicKey getPublicOneTimePrKey() {
        return publicOneTimePrKey;
    }

    public String getOneTimePreKeyID() {
        return oneTimePreKeyID;
    }

}
