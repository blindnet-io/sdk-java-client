package io.blindnet.blindnet.internal;

import io.blindnet.blindnet.exception.KeyStorageException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.*;
import java.security.*;
import java.util.Objects;

import static io.blindnet.blindnet.internal.EncryptionConstants.*;
import static java.util.Objects.requireNonNull;


/**
 * Provides API for key storage.
 */
public class KeyStorage {

    /**
     * todo add readme
     */
    public static final String DEVICE_ID_FILE_NAME = "device_id_file.txt";
    public static final String SIGNING_PRIVATE_KEY_ALIAS = "SIGNING_PRIVATE_KEY";
    public static final String ENCRYPTION_PRIVATE_KEY_ALIAS = "ENCRYPTION_PRIVATE_KEY";

    /**
     * Determines if a key storage is used in Android application.
     */
    public boolean isAndroid = false;

    /**
     * Private constructor as class implements Singleton pattern.
     */
    private KeyStorage() {
    }

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
     * todo javadoc
     * @param deviceId
     */
    public void storeDeviceID(String deviceId) {
        try (PrintWriter out = new PrintWriter(KeyStorageConfig.INSTANCE.getKeyFolderPath() + DEVICE_ID_FILE_NAME)) {
            out.println(deviceId);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public String readDeviceID() {
        return "deviceid";
    }

    /**
     * Stores a private used for encryption.
     *
     * @param privateKey a private key to be stored.
     */
    public void storeEncryptionKey(PrivateKey privateKey) {
        requireNonNull(privateKey, "Encryption private key cannot be null.");

        if (isAndroid) {
            storeKS(privateKey, ENCRYPTION_PRIVATE_KEY_ALIAS);
            return;
        }
        Objects.requireNonNull(KeyStorageConfig.INSTANCE.getKeyFolderPath(), "Key storage not configured properly.");
        store(privateKey, KeyStorageConfig.INSTANCE.getKeyFolderPath() + ENCRYPTION_PRIVATE_KEY_FILENAME);

    }

    /**
     * Returns a private key used for encryption.
     *
     * @return a private key object.
     */
    public PrivateKey readEncryptionPrivateKey() {
        // todo add android reading
        return read(KeyStorageConfig.INSTANCE.getKeyFolderPath() + ENCRYPTION_PRIVATE_KEY_FILENAME);
    }

    /**
     * Stores a private key used for signing.
     *
     * @param privateKey a private key to be stored.
     */
    public void storeSigningKey(PrivateKey privateKey) {
        requireNonNull(privateKey, "Signing private key cannot be null.");

        if (isAndroid) {
            storeKS(privateKey, SIGNING_PRIVATE_KEY_ALIAS);
            return;
        }
        requireNonNull(KeyStorageConfig.INSTANCE.getKeyFolderPath(), "Key storage not configured properly.");
        store(privateKey, KeyStorageConfig.INSTANCE.getKeyFolderPath() + SIGNING_PRIVATE_KEY_FILENAME);
    }

    /**
     * Returns a private key used for signing.
     *
     * @return a private key object.
     */
    public PrivateKey readSigningPrivateKey() {
        // todo add android reading
        return read(KeyStorageConfig.INSTANCE.getKeyFolderPath() + SIGNING_PRIVATE_KEY_FILENAME);
    }

    // todo javaddoc, android support
    public void storeEd25519PrivateKey(PrivateKey privateKey, String keyID) {
        requireNonNull(privateKey, "Private key cannot be null.");
        requireNonNull(privateKey, "Id cannot be null.");

        store(privateKey, KeyStorageConfig.INSTANCE.getKeyFolderPath() + keyID + ".key");
    }

    // todo impl
    public PrivateKey readEd25519PrivateKey() {
        return null;
    }

    /**
     * Stores a public key of a recipient.
     *
     * @param publicKey   a public key to be stored.
     * @param recipientId an id of the recipient.
     */
    public void storeRecipientSigningPublicKey(PublicKey publicKey, String recipientId) {
        requireNonNull(KeyStorageConfig.INSTANCE.getKeyFolderPath(), "Key storage not configured properly.");
        requireNonNull(publicKey, "Recipient signing public key cannot be null.");
        requireNonNull(recipientId, "Recipient Id key cannot be null.");

        // todo add android storing of public key
        store(publicKey, KeyStorageConfig.INSTANCE.getKeyFolderPath() + recipientId + ".key");
    }

    /**
     * Deletes singing public keys of recipients.
     */
    public boolean deleteKeyFolder() {
        requireNonNull(KeyStorageConfig.INSTANCE.getKeyFolderPath(), "Key storage not configured properly.");

        // todo add android support
        return deleteFolder(new File(KeyStorageConfig.INSTANCE.getKeyFolderPath()));
    }

    /**
     * Writes private key to a file.
     *
     * @param key      a key to be stored.
     * @param filepath a path of a file where the private key will be stored.
     */
    private void store(Key key, String filepath) {
        JcaPEMWriter writer = null;
        try {
            writer = new JcaPEMWriter(new OutputStreamWriter(new FileOutputStream(filepath)));
            writer.writeObject(key);
            writer.flush();
        } catch (IOException exception) {
            String msg = "IO Error writing a private key to a file.";
            throw new KeyStorageException(msg);
        } finally {
            close(writer);
        }
    }

    private void storeKS(Key key, String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.setKeyEntry(alias, key, null, null);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
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
            Object keyPair = parser.readObject();
            PrivateKeyInfo keyInfo;
            if (keyPair instanceof PEMKeyPair) {
                keyInfo = ((PEMKeyPair) keyPair).getPrivateKeyInfo();
            } else {
                keyInfo = ((PrivateKeyInfo) keyPair);
            }
            return new JcaPEMKeyConverter().getPrivateKey(keyInfo);
        } catch (FileNotFoundException exception) {
            throw new KeyStorageException("Invalid file path while reading a private key.");
        } catch (IOException exception) {
            throw new KeyStorageException("IO Error while reading a private key.");
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
                String msg = "A PEM writer could not be closed.";
                throw new KeyStorageException(msg);
            }
        }
    }

    /**
     * Deletes folder and it's content.
     *
     * @param folder a folder to be deleted.
     * @return indication if deletion was successful.
     */
    private boolean deleteFolder(File folder) {
        File[] files = folder.listFiles();
        if (files != null) {
            for (File f : files) {
                if (f.isDirectory()) {
                    deleteFolder(f);
                } else {
                    if (!f.delete()) return false;
                }
            }
        }
        return folder.delete();
    }

}
