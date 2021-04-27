package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.KeyEnvelope;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import static io.blindnet.blindnet.domain.EncryptionConstants.SHA_256_ECDSA_ALGORITHM;

/**
 * Provides methods for operations on Key Envelope Object.
 *
 * @author stefanveselinovic
 */
// todo make package access
public class KeyEnvelopeService {

    private static final String ENVELOPE_VERSION = "1.0";

    private EncryptionService encryptionService;
    private SigningService signingService;

    public KeyEnvelopeService() {
        // todo check
        encryptionService = new EncryptionService();
        signingService = new SigningService();
    }

    /**
     * Creates Envelope wrapper object for secret key.
     *
     * @param secretKey           Secret Key to be wrapped.
     * @param encryptionPublicKey Public key used for wrapping of secret key.
     * @param signingPrivateKey   Private key used for signing of envelope.
     * @param ownerId             Owner ID.
     * @param recipientId         Recipient ID.
     * @param senderId            Sender ID.
     * @return Key Envelope object.
     */
    public KeyEnvelope create(SecretKey secretKey,
                              PublicKey encryptionPublicKey,
                              PrivateKey signingPrivateKey,
                              String ownerId,
                              String recipientId,
                              String senderId) {

        KeyEnvelope keyEnvelope = new KeyEnvelope.Builder(UUID.randomUUID().toString())
                .withVersion(ENVELOPE_VERSION)
                .withKey(Base64.getUrlEncoder().encodeToString(encryptionService.wrap(secretKey, encryptionPublicKey)))
                .withOwnerId(ownerId)
                .withRecipientId(recipientId)
                .withSenderId(senderId)
                .timestamp(Instant.now().toEpochMilli())
                .build();

        keyEnvelope.setKeyEnvelopeSignature(sign(keyEnvelope, signingPrivateKey));

        return keyEnvelope;
    }

    /**
     * Verifies key envelope signature,
     *
     * @param keyEnvelope a Key Envelope which signature is being verified.
     * @param signature   a Signature of the Key Envelope.
     * @param publicKey   a Public Key used for signature verification.
     * @return
     */
    public boolean verify(KeyEnvelope keyEnvelope, String signature, PublicKey publicKey) {
        return signingService.verify(keyEnvelope,
                signature,
                publicKey,
                SHA_256_ECDSA_ALGORITHM);
    }

    /**
     * Signs key envelope using provided private key and ECDSA algorithm.
     *
     * @param keyEnvelope Key Envelope object to be signed.
     * @param privateKey  Private Key used for signing.
     * @return Signed Object.
     */
    private String sign(KeyEnvelope keyEnvelope, PrivateKey privateKey) {
        return signingService.sign(keyEnvelope, privateKey, SHA_256_ECDSA_ALGORITHM);
    }

}
