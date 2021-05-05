package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;
import io.blindnet.blindnet.exception.EncryptionException;
import io.blindnet.blindnet.exception.KeyEncryptionException;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jcajce.io.CipherOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
import static java.util.Objects.requireNonNull;

/**
 * Provides API for encryption/decryption related operations.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
class EncryptionService {

    private static final Logger LOGGER = Logger.getLogger(EncryptionService.class.getName());

    private final KeyFactory keyFactory;

    public EncryptionService(KeyFactory keyFactory) {
        this.keyFactory = keyFactory;
    }

    /**
     * Encrypts message and message metadata represented as byte arrays.
     *
     * @param secretKey      a secret key used for encryption.
     * @param messageWrapper a message wrapper.
     * @return encrypted message as byte array.
     */
    public byte[] encryptMessage(SecretKey secretKey, MessageArrayWrapper messageWrapper) {
        requireNonNull(secretKey, "Secret key cannot be null.");
        requireNonNull(messageWrapper, "Message wrapper cannot be null.");

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

    /**
     * Decrypts message and message metadata represented as byte arrays.
     *
     * @param secretKey a secret key used for decryption.
     * @param data      an encrypted data.
     * @return a decrypted message and message metadata as message wrapper object.
     */
    public MessageArrayWrapper decryptMessage(SecretKey secretKey, byte[] data) {
        requireNonNull(secretKey, "Secret key cannot be null.");
        requireNonNull(data, "Input data cannot be null.");

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

    /**
     * Encrypts message and message metadata, where message is provided as an input stream.
     *
     * @param secretKey            a secret key used for encryption.
     * @param messageStreamWrapper a message wrapper.
     * @return a stream of encrypted data.
     */
    public InputStream encryptMessage(SecretKey secretKey, MessageStreamWrapper messageStreamWrapper) {
        requireNonNull(secretKey, "Secret key cannot be null.");
        requireNonNull(messageStreamWrapper, "Message wrapper cannot be null.");

        byte[] metadataLengthBA = ByteBuffer.allocate(4).putInt(messageStreamWrapper.getMetadata().length).array();

        InputStream metadataInputStream = new ByteArrayInputStream(ByteBuffer
                .allocate(metadataLengthBA.length + messageStreamWrapper.getMetadata().length)
                .put(metadataLengthBA)
                .put(messageStreamWrapper.getMetadata())
                .array());

        try {
            byte[] iv = keyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, GCM_IV_LENGTH);
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

    /**
     * Decrypts message and message data, where message is provided as an input stream.
     *
     * @param secretKey a secret key used for decryption.
     * @param input     an input stream which provides encrypted message and message metadata.
     * @return a decrypted message and message metadata as message wrapper object.
     */
    public MessageStreamWrapper decryptMessage(SecretKey secretKey, InputStream input) {
        requireNonNull(secretKey, "Secret key cannot be null.");
        requireNonNull(input, "Input stream cannot be null.");

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
     * Encrypts data represented as byte array using AES/GCM encryption algorithm.
     *
     * @param secretKey a secret key used for encryption.
     * @param data      a data to be encrypted.
     * @return an encrypted data as byte array.
     */
    public byte[] encrypt(SecretKey secretKey, byte[] data) {
        requireNonNull(secretKey, "Secret key cannot be null.");
        requireNonNull(data, "Input data cannot be null.");

        try {
            byte[] iv = keyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, GCM_IV_LENGTH);
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
     * Decrypts data represented as byte array using AES/GCM encryption algorithm.
     *
     * @param secretKey a secret key used for encryption.
     * @param data      a data to be decrypted.
     * @return a decrypted data as byte array.
     */
    public byte[] decrypt(SecretKey secretKey, byte[] data) {
        requireNonNull(secretKey, "Secret key cannot be null.");
        requireNonNull(data, "Input data cannot be null.");

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
     * Wraps secret key using public key.
     *
     * @param secretKey a secret key to be wrapped.
     * @param publicKey a public key used to wrap secret key.
     * @return a wrapped secret key as byte array.
     */
    public byte[] wrap(SecretKey secretKey, PublicKey publicKey) {
        requireNonNull(secretKey, "Secret key cannot be null.");
        requireNonNull(publicKey, "Public key cannot be null.");

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
     * Unwraps secret key using private key.
     *
     * @param wrappedKey a wrapped secret key.
     * @param privateKey a private key used for unwrapping.
     * @return a key object.
     */
    public Key unwrap(byte[] wrappedKey, PrivateKey privateKey) {
        requireNonNull(wrappedKey, "Wrapped key cannot be null.");
        requireNonNull(privateKey, "Private key cannot be null.");

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
