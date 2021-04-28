package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;
import io.blindnet.blindnet.exception.EncryptionException;
import io.blindnet.blindnet.exception.KeyEncryptionException;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jcajce.io.CipherOutputStream;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
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
    public byte[] encryptMessage(SecretKey secretKey, MessageArrayWrapper messageWrapper) {

        byte[] metadataLengthBA = ByteBuffer.allocate(4).putInt(messageWrapper.getMetadata().length).array();

        /*
         * Creates data array of:
         * 1. a length of message metadata
         * 2. a message metadata
         * 3. a message data
         */
        byte[] data = ByteBuffer.allocate(metadataLengthBA.length +
                messageWrapper.getMetadata().length +
                messageWrapper.getData().length)
                .put(metadataLengthBA)
                .put(messageWrapper.getMetadata())
                .put(messageWrapper.getData())
                .array();

        return encrypt(secretKey, data);
    }

    public MessageArrayWrapper decryptMessage(SecretKey secretKey, byte[] data) {
        ByteBuffer decryptedDataWrapper = ByteBuffer.wrap(
                requireNonNull(decrypt(secretKey, data)));

        /*
         * 1. reads a length of message metadata
         * 2. based on step 1 reads message metadata
         * 3. reads a message data which is what is left in the input
         */
        byte[] decryptedMetadataLengthBA = new byte[4];
        decryptedDataWrapper.get(decryptedMetadataLengthBA);
        int metadataLength = ByteBuffer.wrap(decryptedMetadataLengthBA).getInt();

        byte[] decryptedMetadata = new byte[metadataLength];
        decryptedDataWrapper.get(decryptedMetadata);

        byte[] decryptedData = new byte[decryptedDataWrapper.remaining()];
        decryptedDataWrapper.get(decryptedData);

        return new MessageArrayWrapper(decryptedMetadata, decryptedData);
    }

    public InputStream encryptMessage(SecretKey secretKey, MessageStreamWrapper messageStreamWrapper) {
        byte[] metadataLengthBA = ByteBuffer.allocate(4).putInt(messageStreamWrapper.getMetadata().length).array();

        InputStream metadataInputStream = new ByteArrayInputStream(ByteBuffer
                .allocate(metadataLengthBA.length + messageStreamWrapper.getMetadata().length)
                .put(metadataLengthBA)
                .put(messageStreamWrapper.getMetadata())
                .array());

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            byte[] iv = KeyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, GCM_IV_LENGTH);
            /*
             * 1. writes IV
             * 2. encrypts a length of message metadata and message metadata
             * 3. encrypts message stream data
             */

            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_T_LENGTH, iv));

            PipedOutputStream pipedOutputStream = new PipedOutputStream();
            PipedInputStream pipedInputStream = new PipedInputStream(pipedOutputStream);
            pipedOutputStream.write(iv);
            try (CipherOutputStream cipherOut = new CipherOutputStream(pipedOutputStream, cipher)) {

                byte[] buf = new byte[4096];
                int length;
                while ((length = metadataInputStream.read(buf)) > 0) {
                    cipherOut.write(buf, 0, length);
                }
                metadataInputStream.close();

                buf = new byte[4096];
                while ((length = messageStreamWrapper.getData().read(buf)) > 0) {
                    cipherOut.write(buf, 0, length);
                }
                messageStreamWrapper.getData().close();

                return pipedInputStream;
            }
        } catch (Exception exception) {
            String msg = "Error during encryption. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new EncryptionException(msg, exception);
        }
    }

    public MessageStreamWrapper decryptMessage(SecretKey secretKey, InputStream input) {
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] metadataLengthBA = new byte[4];

        try {
            /*
             * 1. reads IV
             * 2. decrypts a length of message metadata
             * 3. based on step 2 decrypts message metadata
             * 4. decrypts message input stream which is what is left in the input
             */
            input.read(iv);

            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_T_LENGTH, iv));

            PipedOutputStream pipedOutputStream = new PipedOutputStream();
            PipedInputStream pipedInputStream = new PipedInputStream(pipedOutputStream);

            try (CipherInputStream cipherIn = new CipherInputStream(input, cipher)) {
                cipherIn.read(metadataLengthBA);

                byte[] metadata = new byte[ByteBuffer.wrap(metadataLengthBA).getInt()];
                cipherIn.read(metadata);

                byte[] buf = new byte[4096];
                int length;
                while ((length = cipherIn.read(buf)) > 0) {
                    pipedOutputStream.write(buf, 0, length);
                }
                pipedOutputStream.close();
                return new MessageStreamWrapper(metadata, pipedInputStream);
            }
        } catch (Exception exception) {
            String msg = "Error during decryption. " + exception.getMessage();
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
