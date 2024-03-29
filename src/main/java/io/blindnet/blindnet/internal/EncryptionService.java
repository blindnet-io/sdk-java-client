package io.blindnet.blindnet.internal;

import io.blindnet.blindnet.domain.message.MessageArrayWrapper;
import io.blindnet.blindnet.domain.message.MessageStreamWrapper;
import io.blindnet.blindnet.exception.EncryptionException;
import io.blindnet.blindnet.exception.KeyEncryptionException;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.HttpURLConnection;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import static io.blindnet.blindnet.internal.EncryptionConstants.*;
import static java.util.Objects.requireNonNull;

/**
 * Provides API for encryption and decryption operations.
 */
public class EncryptionService {

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
    public byte[] encryptMessage(final SecretKey secretKey, final MessageArrayWrapper messageWrapper) {
        requireNonNull(secretKey, "Secret key cannot be null.");
        requireNonNull(messageWrapper, "Message wrapper cannot be null.");
        return encrypt(secretKey, messageWrapper.prepare());
    }

    /**
     * Decrypts message and message metadata represented as byte arrays.
     *
     * @param secretKey a secret key used for decryption.
     * @param data      an encrypted data.
     * @return a decrypted message and message metadata as message wrapper object.
     */
    public MessageArrayWrapper decryptMessage(final SecretKey secretKey, final byte[] data) {
        requireNonNull(secretKey, "Secret key cannot be null.");
        requireNonNull(data, "Input data cannot be null.");

        return MessageArrayWrapper.process(ByteBuffer.wrap(
                requireNonNull(decrypt(secretKey, data))));
    }

    /**
     * Encrypts message and message metadata, where message is provided as an input stream.
     *
     * @param secretKey            a secret key used for encryption.
     * @param messageStreamWrapper a message wrapper.
     * @return a stream of encrypted data.
     */
    public InputStream encryptMessage(final SecretKey secretKey, final MessageStreamWrapper messageStreamWrapper) {
        requireNonNull(secretKey, "Secret key cannot be null.");
        requireNonNull(messageStreamWrapper, "Message wrapper cannot be null.");

        byte[] metadataBA = new JSONObject(messageStreamWrapper.getMetadata()).toString().getBytes();
        byte[] metadataLengthBA = ByteBuffer.allocate(4).putInt(metadataBA.length).array();

        InputStream metadataInputStream = new ByteArrayInputStream(ByteBuffer
                .allocate(metadataLengthBA.length + metadataBA.length)
                .put(metadataLengthBA)
                .put(metadataBA)
                .array());

        try {
            /*
             * 1. writes IV
             * 2. encrypts a length of message metadata and message metadata
             * 3. encrypts message stream data
             */
            byte[] iv = keyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, GCM_IV_LENGTH);
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
            throw new EncryptionException("Error during encryption.");
        }
    }

    /**
     * Decrypts message and message data, where message is provided as an input stream.
     *
     * @param secretKey a secret key used for decryption.
     * @param input     an input stream which provides encrypted message and message metadata.
     * @return a decrypted message and message metadata as message wrapper object.
     */
    public MessageStreamWrapper decryptMessage(final SecretKey secretKey, final InputStream input) {
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
                return new MessageStreamWrapper(new JSONObject(new String(metadata)).toMap(), pipedInputStream);
            }
        } catch (Exception exception) {
            throw new EncryptionException("Error during message decryption.");
        }
    }

    /**
     * Encrypts data provided as an input stream.
     *
     * @param secretKey a secret key used for encryption.
     * @param input an input stream of data that will be encrypted.
     * @return a stream of encrypted data.
     */
    public InputStream encrypt(final SecretKey secretKey, final InputStream input) {
        requireNonNull(secretKey, "Secret key cannot be null.");
        requireNonNull(input, "Input cannot be null.");

        try {
            byte[] iv = keyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, GCM_IV_LENGTH);
            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_T_LENGTH, iv));
            PipedOutputStream pipedOutputStream = new PipedOutputStream();
            PipedInputStream pipedInputStream = new PipedInputStream(pipedOutputStream);
            pipedOutputStream.write(iv);

            try (CipherOutputStream cipherOut = new CipherOutputStream(pipedOutputStream, cipher)) {
                byte[] buf = new byte[4096];
                int length;
                while ((length = input.read(buf)) > 0) {
                    cipherOut.write(buf, 0, length);
                }
                input.close();

                return pipedInputStream;
            }
        } catch (Exception exception) {
            throw new EncryptionException("Error during encryption.");
        }
    }

    /**
     * Decrypts data provided within a Http connection.
     *
     * @param secretKey a secret key used for decryption.
     * @param con a http connection that provides data through input stream.
     * @return a stream of encrypted data.
     */
    public InputStream decrypt(final SecretKey secretKey, final HttpURLConnection con) {
        requireNonNull(secretKey, "Secret key cannot be null.");
        requireNonNull(con, "Connection cannot be null.");

        byte[] iv = new byte[GCM_IV_LENGTH];
        try {
            InputStream input = con.getInputStream();
            input.read(iv);

            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_T_LENGTH, iv));

            PipedOutputStream pipedOutputStream = new PipedOutputStream();
            PipedInputStream pipedInputStream = new PipedInputStream(pipedOutputStream);

            try (CipherInputStream cipherIn = new CipherInputStream(input, cipher)) {
                byte[] buf = new byte[4096];
                int length;
                while ((length = cipherIn.read(buf)) > 0) {
                    pipedOutputStream.write(buf, 0, length);
                }
                pipedOutputStream.close();
                con.disconnect();
                return pipedInputStream;
            }
        } catch (Exception exception) {
            throw new EncryptionException("Error during message decryption.");
        }
    }

    /**
     * Encrypts data represented as byte array using AES/GCM encryption algorithm.
     *
     * @param secretKey a secret key used for encryption.
     * @param data      a data to be encrypted.
     * @return an encrypted data as byte array.
     */
    public byte[] encrypt(final SecretKey secretKey, final byte[] data) {
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
            throw new EncryptionException("Error during encryption.");
        }
    }

    /**
     * Decrypts data represented as byte array using AES/GCM encryption algorithm.
     *
     * @param secretKey a secret key used for encryption.
     * @param data      a data to be decrypted.
     * @return a decrypted data as byte array.
     */
    public byte[] decrypt(final SecretKey secretKey, final byte[] data) {
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
            throw new EncryptionException("Error during decryption.");
        }
    }

    /**
     * Encrypts data using RSA OAEP algorithm.
     *
     * @param publicKey a public key used to encrypt data.
     * @param data      a data to be encrypted.
     * @return a encrypted data.
     */
    public byte[] encrypt(final PublicKey publicKey, final byte[] data) {
        requireNonNull(publicKey, "Public key cannot be null.");
        requireNonNull(data, "Data cannot be null.");

        try {
            Cipher c = Cipher.getInstance("RSA/NONE/OAEPPadding", BC_PROVIDER);
            c.init(Cipher.ENCRYPT_MODE, publicKey);
            return c.doFinal(data);
        } catch (GeneralSecurityException exception) {
            throw new KeyEncryptionException("Error while wrapping secret key.");
        }
    }

    /**
     * Decrypts data using RSA OAEP algorithm.
     *
     * @param privateKey a private key used for decryption.
     * @param data       a data to be decrypted.
     * @return a decrypted data.
     */
    public byte[] decrypt(final PrivateKey privateKey, final byte[] data) {
        requireNonNull(privateKey, "Private key cannot be null.");
        requireNonNull(data, "Data key cannot be null.");

        try {
            Cipher c = Cipher.getInstance("RSA/NONE/OAEPPadding", BC_PROVIDER);
            c.init(Cipher.DECRYPT_MODE, privateKey);
            return c.doFinal(data);
        } catch (GeneralSecurityException exception) {
            throw new KeyEncryptionException("Error while unwrapping secret key.");
        }
    }

}
