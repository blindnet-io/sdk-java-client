package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.exception.KeyConstructionException;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Provides API for operations with EC public keys.
 */
class SignalKeyFactory {

    /**
     * Converts byte encoded public key.
     *
     * @param publicKey an ec public key in a form of byte array.
     * @return ec public key object.
     */
    public ECPublicKey convertToECPublicKey(byte[] publicKey) {
        try {
            return Curve.decodePoint(ByteBuffer.allocate(33)
                    .put((byte) Curve.DJB_TYPE)
                    .put(publicKey)
                    .array(), 0);
        } catch (InvalidKeyException e) {
            throw new KeyConstructionException("Unable to decode EC public key.");
        }
    }

    /**
     * Removes a leading byte of the provided public key.
     *
     * @param publicKey a public key in form of byte array.
     * @return a transformed public key as byte array.
     */
    public byte[] removeKeyTypeByte(byte[] publicKey) {
        return Arrays.copyOfRange(publicKey, 1, publicKey.length);
    }
}
