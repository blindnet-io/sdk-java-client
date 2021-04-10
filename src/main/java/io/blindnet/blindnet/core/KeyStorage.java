package io.blindnet.blindnet.core;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.*;
import java.security.PrivateKey;
import java.util.Objects;

/**
 * Provides api for private key storage.
 *
 * @author stefanveselinovic
 */
class KeyStorage {

    //todo add java doc

    public KeyStorage() { }

    public void storeEncryptionKey(PrivateKey privateKey) {
        Objects.requireNonNull(KeyStorageConfig.INSTANCE.getEncryptionPrivateKeyPath(), "Encryption private key file path cannot be null.");
        Objects.requireNonNull(privateKey, "Encryption private key cannot be null.");

        store(privateKey, KeyStorageConfig.INSTANCE.getEncryptionPrivateKeyPath());
    }

    public void storeSigningKey(PrivateKey privateKey) {
        Objects.requireNonNull(KeyStorageConfig.INSTANCE.getSigningPrivateKeyPath(), "Signing private key file path cannot be null.");
        Objects.requireNonNull(privateKey, "Signing private key cannot be null.");

        store(privateKey, KeyStorageConfig.INSTANCE.getSigningPrivateKeyPath());
    }

    private void store(PrivateKey privateKey, String filepath) {
        JcaPEMWriter writer = null;
        try {
            writer = new JcaPEMWriter(new OutputStreamWriter(new FileOutputStream(filepath)));
            writer.writeObject(privateKey);
            writer.flush();
        } catch (IOException exception) {
            //todo log and throw exception
        } finally {
            close(writer);
        }
    }

    private void close(JcaPEMWriter writer) {
        if (writer != null) {
            try {
                writer.close();
            } catch (IOException exception) {
                //todo log and throw exception
            }
        }
    }

}
