package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.KeyEnvelope;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import static io.blindnet.blindnet.domain.EncryptionConstants.Ed25519_ALGORITHM;

/**
 * Provides API for operations related to Key Envelope Object.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
class KeyEnvelopeService {

    private static final String ENVELOPE_VERSION = "1.0";

    private final EncryptionService encryptionService;
    private final SigningService signingService;

    public KeyEnvelopeService() {
        encryptionService = new EncryptionService(new KeyFactory());
        signingService = new SigningService();
    }

    /**
     * Creates Envelope wrapper object for secret key.
     *
     * @param secretKey           a secret key to be wrapped.
     * @param encryptionPublicKey a public key used for wrapping of secret key.
     * @param signingPrivateKey   a private key used for signing of envelope.
     * @param ownerId             an id of the owner.
     * @param recipientId         an id of the recipient.
     * @param senderId            an id of the sender.
     * @return a key envelope object.
     */
    public KeyEnvelope create(SecretKey secretKey,
                              PublicKey encryptionPublicKey,
                              PrivateKey signingPrivateKey,
                              String ownerId,
                              String recipientId,
                              String senderId) {

        KeyEnvelope keyEnvelope = new KeyEnvelope.Builder(UUID.randomUUID().toString())
                .withVersion(ENVELOPE_VERSION)
                .withKey(Base64.getEncoder().encodeToString(encryptionService.wrap(secretKey, encryptionPublicKey)))
                .withOwnerId(ownerId)
                .withRecipientId(recipientId)
                .withSenderId(senderId)
                .timestamp(Instant.now().toEpochMilli())
                .build();

        keyEnvelope.setKeyEnvelopeSignature(sign(keyEnvelope, signingPrivateKey, Ed25519_ALGORITHM));

        return keyEnvelope;
    }

    /**
     * Verifies key envelope signature,
     *
     * @param keyEnvelope a key envelope which signature is being verified.
     * @param signature   a signature of the Key Envelope.
     * @param publicKey   a public key used for signature verification.
     * @return a indication if signature is valid.
     */
    public boolean verify(KeyEnvelope keyEnvelope, String signature, PublicKey publicKey) {
        return signingService.verify(keyEnvelope,
                signature,
                publicKey,
                Ed25519_ALGORITHM);
    }

    /**
     * Signs key envelope using provided private key and ECDSA algorithm.
     *
     * @param keyEnvelope a key envelope object to be signed.
     * @param privateKey  a private Key used for signing.
     * @return a envelope signature.
     */
    private String sign(KeyEnvelope keyEnvelope, PrivateKey privateKey, String algorithm) {
        return Base64.getEncoder().encodeToString(signingService.sign(keyEnvelope, privateKey, algorithm));
    }

}
