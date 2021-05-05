package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.KeyStorageException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.*;
import java.security.PrivateKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;

/**
 * Provides API for private key storage.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
class KeyStorage {

    private static final Logger LOGGER = Logger.getLogger(KeyFactory.class.getName());

    /**
     * Private constructor as class implements Singleton pattern.
     */
    private KeyStorage() {}

    /**
     * Inner class which holds Singleton instance.
     */
    private static class InstanceHolder {
        public static final KeyStorage instance = new KeyStorage();
    }

    /**
     * Returns Singleton instance of the class.
     *
     * @return Key Storage object.
     */
    public static KeyStorage getInstance() {
        return InstanceHolder.instance;
    }

    /**
     * Stores a private used for encryption.
     *
     * @param privateKey a private key to be stored.
     */
    public void storeEncryptionKey(PrivateKey privateKey) {
        requireNonNull(KeyStorageConfig.INSTANCE.getEncryptionPrivateKeyPath(), "Key storage not configured properly.");
        requireNonNull(privateKey, "Encryption private key cannot be null.");

        store(privateKey, KeyStorageConfig.INSTANCE.getEncryptionPrivateKeyPath());
    }

    /**
     * Returns a private key used for encryption.
     *
     * @return a private Key object.
     */
    public PrivateKey readEncryptionPrivateKey() {
        return read(KeyStorageConfig.INSTANCE.getEncryptionPrivateKeyPath());
    }

    /**
     * Deletes private key used for encryption.
     *
     * @return indication if deletion was successful.
     */
    public boolean deleteEncryptionKey() {
        return new File(KeyStorageConfig.INSTANCE.getEncryptionPrivateKeyPath()).delete();
    }

    /**
     * Stores a private key used for signing.
     *
     * @param privateKey a private key to be stored.
     */
    public void storeSigningKey(PrivateKey privateKey) {
        requireNonNull(KeyStorageConfig.INSTANCE.getSigningPrivateKeyPath(), "Key storage not configured properly.");
        requireNonNull(privateKey, "Signing private key cannot be null.");

        store(privateKey, KeyStorageConfig.INSTANCE.getSigningPrivateKeyPath());
    }

    /**
     * Returns a private key used for signing.
     *
     * @return a private key object.
     */
    public PrivateKey readSigningPrivateKey() {
        return read(KeyStorageConfig.INSTANCE.getSigningPrivateKeyPath());
    }

    /**
     * Deletes private key used for signing.
     *
     * @return indication if deletion was successful.
     */
    public boolean deleteSigningKey() {
        return new File(KeyStorageConfig.INSTANCE.getSigningPrivateKeyPath()).delete();
    }

    /**
     * Writes private key to a file.
     *
     * @param privateKey a private key to be stored.
     * @param filepath a path of a file where the private key will be stored.
     */
    private void store(PrivateKey privateKey, String filepath) {
        JcaPEMWriter writer = null;
        try {
            writer = new JcaPEMWriter(new OutputStreamWriter(new FileOutputStream(filepath)));
            writer.writeObject(privateKey);
            writer.flush();
        } catch (IOException exception) {
            String msg = "IO Error writing a private key to a file. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyStorageException(msg, exception);
        } finally {
            close(writer);
        }
    }

    /**
     * Reads private key from a file.
     *
     * @param filepath a path of a file which contains private key.
     * @return a private key object.
     */
    private PrivateKey read(String filepath) {
        try {
            PEMParser parser = new PEMParser(new InputStreamReader(new FileInputStream(filepath)));
            PEMKeyPair pemKeyPair = (PEMKeyPair)parser.readObject();
            return new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        } catch (FileNotFoundException exception) {
            String msg = "Invalid file path while reading a private key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyStorageException(msg, exception);
        } catch (IOException exception) {
            String msg = "IO Error while reading a private key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyStorageException(msg, exception);
        }
    }

    /**
     * Closes PEM writer properly.
     *
     * @param writer PEM writer to be closed.
     */
    private void close(JcaPEMWriter writer) {
        if (writer != null) {
            try {
                writer.close();
            } catch (IOException exception) {
                String msg = "A PEM writer could not be closed. " + exception.getMessage();
                LOGGER.log(Level.SEVERE, msg);
                throw new KeyStorageException(msg, exception);
            }
        }
    }

}
