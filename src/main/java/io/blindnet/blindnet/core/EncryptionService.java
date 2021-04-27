package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.MessageWrapper;
import io.blindnet.blindnet.exception.EncryptionException;
import io.blindnet.blindnet.exception.KeyEncryptionException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
import static java.util.Objects.requireNonNull;

/**
 * todo javadoc
 * todo package view not public
 *
 * @author stefanveselinovic
 */
public class EncryptionService {

    private static final Logger LOGGER = Logger.getLogger(EncryptionService.class.getName());

    /**
     * todo javadoc
     *
     * @param secretKey
     * @param messageWrapper
     * @return
     */
    public byte[] encryptMessage(SecretKey secretKey, MessageWrapper messageWrapper) {

        byte[] metadataLengthBA = ByteBuffer.allocate(4).putInt(messageWrapper.getMetadata().length).array();

        // data to be encrypted -> metadata length + metadata + data
        byte[] data = ByteBuffer.allocate(metadataLengthBA.length +
                messageWrapper.getMetadata().length +
                messageWrapper.getData().length)
                .put(metadataLengthBA)
                .put(messageWrapper.getMetadata())
                .put(messageWrapper.getData())
                .array();

        return encrypt(secretKey, data);
    }

    public MessageWrapper decryptMessage(SecretKey secretKey, byte[] data) {
        ByteBuffer decryptedDataWrapper = ByteBuffer.wrap(
                requireNonNull(decrypt(secretKey, data)));

        byte[] decryptedMetadataLengthBA = new byte[4];
        decryptedDataWrapper.get(decryptedMetadataLengthBA);
        int metadataLength = ByteBuffer.wrap(decryptedMetadataLengthBA).getInt();

        byte[] decryptedMetadata = new byte[metadataLength];
        decryptedDataWrapper.get(decryptedMetadata);

        byte[] decryptedData = new byte[decryptedDataWrapper.remaining()];
        decryptedDataWrapper.get(decryptedData);

        return new MessageWrapper(decryptedMetadata, decryptedData);
    }

    /**
     * todo javadoc and exception handling
     *
     * @param secretKey
     * @param data
     * @return
     */
    public byte[] encrypt(SecretKey secretKey, byte[] data) {
        try {
            byte[] iv = KeyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, GCM_IV_LENGTH);
            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_T_LENGTH, iv));

            byte[] encryptedData = cipher.doFinal(data);

            return ByteBuffer.allocate(iv.length + encryptedData.length)
                    .put(iv)
                    .put(encryptedData)
                    .array();

        } catch (GeneralSecurityException exception) {
            String msg = "Error during encryption. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new EncryptionException(msg, exception);
        }
    }

    /**
     * todo javadoc and exception handling
     *
     * @param secretKey
     * @param data
     * @return
     */
    public byte[] decrypt(SecretKey secretKey, byte[] data) {

        try {
            ByteBuffer encryptedDataWrapper = ByteBuffer.wrap(data);
            byte[] iv = new byte[GCM_IV_LENGTH];
            encryptedDataWrapper.get(iv);

            byte[] encryptedData = new byte[encryptedDataWrapper.remaining()];
            encryptedDataWrapper.get(encryptedData);

            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_T_LENGTH, iv));

            return cipher.doFinal(encryptedData);

        } catch (GeneralSecurityException exception) {
            String msg = "Error during decryption. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new EncryptionException(msg, exception);
        }
    }

    /**
     * todo javadoc
     *
     * @param secretKey
     * @param publicKey
     * @return
     */
    public byte[] wrap(SecretKey secretKey, PublicKey publicKey) {

        // todo check padding, check oaep parameters specification
        try {
            Cipher c = Cipher.getInstance("RSA/NONE/OAEPPadding", BC_PROVIDER);
            c.init(Cipher.WRAP_MODE, publicKey);
//        c.init(Cipher.WRAP_MODE, publicKey,
//                new OAEPParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"),
//                        PSource.PSpecified.DEFAULT));
            return c.wrap(secretKey);
        } catch (GeneralSecurityException exception) {
            String msg = "Error while wrapping secret key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyEncryptionException(msg, exception);
        }
    }

    /**
     * todo javadoc
     *
     * @param wrappedKey
     * @param privateKey
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    public Key unwrap(byte[] wrappedKey, PrivateKey privateKey) {
        // todo check algs
        try {
            Cipher c = Cipher.getInstance("RSA/NONE/OAEPPadding", BC_PROVIDER);
            c.init(Cipher.UNWRAP_MODE, privateKey);
            return c.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
        } catch (GeneralSecurityException exception) {
            String msg = "Error while unwrapping secret key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyEncryptionException(msg, exception);
        }
    }

}
