package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.KeyEnvelope;
import io.blindnet.blindnet.exception.KeyEncryptionException;
import io.blindnet.blindnet.exception.SignatureException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.blindnet.blindnet.domain.EncryptionConstants.SHA_256_ECDSA_ALGORITHM;

/**
 * Provides methods for operations on Key Envelope Object.
 *
 * @author stefanveselinovic
 */
// todo make package access
public class KeyEnvelopeService {

    private static final Logger LOGGER = Logger.getLogger(JwtService.class.getName());
    private static final String ENVELOPE_VERSION = "1.0";

    private EncryptionService encryptionService;

    public KeyEnvelopeService() {
        // todo check
        this.encryptionService = new EncryptionService();
    }

    /**
     * Creates Envelope wrapper object for secret key.
     *
     * @param secretKey   Secret Key to be wrapped.
     * @param encryptionPublicKey   Public key used for wrapping of secret key.
     * @param signingPrivateKey  Private key used for signing of envelope.
     * @param ownerId     Owner ID.
     * @param recipientId Recipient ID.
     * @param senderId    Sender ID.
     * @return Key Envelope object.
     */
    public KeyEnvelope create(SecretKey secretKey,
                              PublicKey encryptionPublicKey,
                              PrivateKey signingPrivateKey,
                              String ownerId,
                              String recipientId,
                              String senderId) {

        try {
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
        } catch (NoSuchPaddingException exception) {
            String msg = "Invalid padding Error while wrapping secret key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyEncryptionException(msg, exception);
        } catch (NoSuchAlgorithmException exception) {
            String msg = "Invalid algorithm Error while wrapping secret key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyEncryptionException(msg, exception);
        } catch (InvalidKeyException exception) {
            String msg = "Invalid Key Error while wrapping secret key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyEncryptionException(msg, exception);
        } catch (NoSuchProviderException exception) {
            String msg = "Invalid Provider Error while wrapping secret key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyEncryptionException(msg, exception);
        } catch (IllegalBlockSizeException exception) {
            String msg = "Invalid Block Size Error while wrapping secret key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyEncryptionException(msg, exception);
        }
    }

    /**
     * Verifies key envelope signature,
     *
     * @param keyEnvelope a Key Envelope which signature is being verified.
     * @param signature a Signature of the Key Envelope.
     * @param publicKey a Public Key used for signature verification.
     * @return
     */
    public boolean verify(KeyEnvelope keyEnvelope, String signature, PublicKey publicKey) {

        try {
            return encryptionService.verify(keyEnvelope,
                    signature,
                    publicKey,
                    SHA_256_ECDSA_ALGORITHM);
        } catch (InvalidKeyException exception) {
            String msg = "Invalid Key Error while verifying key envelope signature. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new SignatureException(msg, exception);
        } catch (java.security.SignatureException exception) {
            String msg = "Signature construction Error while verifying key envelope signature. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new SignatureException(msg, exception);
        }
    }

    /**
     * Signs key envelope using provided private key and ECDSA algorithm.
     *
     * @param keyEnvelope Key Envelope object to be signed.
     * @param privateKey  Private Key used for signing.
     * @return Signed Object.
     */
    private String sign(KeyEnvelope keyEnvelope, PrivateKey privateKey) {

        try {
            return encryptionService.sign(keyEnvelope, privateKey, SHA_256_ECDSA_ALGORITHM);
        } catch (InvalidKeyException exception) {
            String msg = "Invalid private key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new SignatureException(msg, exception);
        } catch (IOException exception) {
            String msg = "IO Error during signature creation. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new SignatureException(msg, exception);
        } catch (java.security.SignatureException exception) {
            String msg = "Unable to calculate signature. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new SignatureException(msg, exception);
        }
    }

}
