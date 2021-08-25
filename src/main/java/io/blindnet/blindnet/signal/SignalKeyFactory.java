package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.exception.KeyConstructionException;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.whispersystems.curve25519.java.ge_p3;
import org.whispersystems.curve25519.java.ge_p3_tobytes;
import org.whispersystems.curve25519.java.ge_scalarmult_base;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static io.blindnet.blindnet.internal.EncryptionConstants.Ed25519_ALGORITHM;

public class SignalKeyFactory {

    // todo remove
    public PrivateKey convertToPrivateKey(byte[] ecPrivateKey) {
        try {
            PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                    new DEROctetString(ecPrivateKey));
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance(Ed25519_ALGORITHM);
            return kf.generatePrivate(pkcs8KeySpec);
        } catch (IOException | GeneralSecurityException exception) {
            throw new KeyConstructionException("Error while converting to private key.");
        }
    }

    // todo remove
    public PublicKey convertToPublicKey(byte[] ecPublicKey) {
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance(Ed25519_ALGORITHM);
            SubjectPublicKeyInfo pubKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                    ecPublicKey);
            return kf.generatePublic(new X509EncodedKeySpec(pubKeyInfo.getEncoded()));

        } catch (IOException | GeneralSecurityException exception) {
            throw new KeyConstructionException("Error while converting to public key.");
        }
    }

    // todo javadoc, exception handl
    public ECPublicKey convertToECPublicKey(byte[] publicKey) {
        try {
            return Curve.decodePoint(ByteBuffer.allocate(33)
                    .put((byte) Curve.DJB_TYPE)
                    .put(publicKey)
                    .array(), 0);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] removeKeyTypeByte(byte[] publicKey) {
        return Arrays.copyOfRange(publicKey, 1, publicKey.length);
    }

    private static byte[] x509ToRaw(byte[] key) throws Exception {
        X25519PublicKeyParameters x25519PublicKeyParameters = (X25519PublicKeyParameters) PublicKeyFactory.createKey(key);
        return x25519PublicKeyParameters.getEncoded();
    }

    private static PublicKey rawToX509(byte[] key) throws Exception {
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("X25519");
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), key);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        return publicKey;
    }

    public byte[] extractEd25519PublicKeyFromIdentity25519PrivateKey(byte[] privateKey) {
        ge_p3 ed_pubkey_point = new ge_p3(); /* Ed25519 pubkey point */
        byte[] ed_pubkey = new byte[32]; /* Ed25519 encoded pubkey */
        ge_scalarmult_base.ge_scalarmult_base(ed_pubkey_point, privateKey);
        ge_p3_tobytes.ge_p3_tobytes(ed_pubkey, ed_pubkey_point);
        return ed_pubkey;
    }
}
