package io.blindnet.blindnet.domain;

import org.whispersystems.libsignal.ecc.ECPublicKey;

/**
 * A wrapper class for user's public keys retrieved from Blindnet server.
 */
public class BlindnetSignalPublicKeys {

    /**
     * The ID of the user.
     */
    private final String userID;

    /**
     * The ID of the user's device.
     */
    private final String deviceID;

    /**
     * The identity ID.
     */
    private final String identityID;

    /**
     * The public identity key of the user.
     */
    private final ECPublicKey publicIdentityKey;

    /**
     * The ID of the pre key pair.
     */
    private final String preKeyPairID;

    /**
     * The public pre key object.
     */
    private final ECPublicKey publicPreKey;

    /**
     * Pre key signature value.
     */
    private final byte[] preKeySignature;

    /**
     * The ID of the one time pre key.
     */
    private final String oneTimePreKeyID;

    /**
     * The public one time pre key object.
     */
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
