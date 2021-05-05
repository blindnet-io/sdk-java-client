package io.blindnet.blindnet.core;

import io.blindnet.blindnet.KeyEncryptionService;
import io.blindnet.blindnet.domain.PrivateKeyPair;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.util.Base64;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;

/**
 * Provides API for encryption and decryption of user private keys.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public class KeyEncryptionServiceImpl implements KeyEncryptionService {

    private final KeyStorage keyStorage;
    private final KeyFactory keyFactory;
    private final EncryptionService encryptionService;
    private final BlindnetClient blindnetClient;

    public KeyEncryptionServiceImpl(KeyStorage keyStorage,
                                    KeyFactory keyFactory,
                                    EncryptionService encryptionService,
                                    BlindnetClient blindnetClient) {

        this.keyStorage = keyStorage;
        this.keyFactory = keyFactory;
        this.encryptionService = encryptionService;
        this.blindnetClient = blindnetClient;
    }

    /**
     * Encrypts user's private keys and sends them to Blindnet API.
     *
     * @param password a password phrase used for encryption.
     */
    @Override
    public void encrypt(String password) {
        byte[] salt = keyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, SALT_LENGTH);

        SecretKey secretKey = keyFactory.getAESKeyFromPassword(password.toCharArray(),
                salt,
                PBKDF_SHA256);

        PrivateKey encryptionPrivateKey = keyStorage.readEncryptionPrivateKey();
        PrivateKey signingPrivateKey = keyStorage.readSigningPrivateKey();

        byte[] encryptedEPK = encryptionService.encrypt(secretKey, encryptionPrivateKey.getEncoded());
        String encryptedEKPBase64 = Base64.getUrlEncoder()
                .encodeToString(ByteBuffer
                        .allocate(salt.length + encryptedEPK.length)
                        .put(salt)
                        .put(encryptedEPK)
                        .array());

        byte[] encryptedSPK = encryptionService.encrypt(secretKey, signingPrivateKey.getEncoded());
        String encryptedSKPBase64 = Base64.getUrlEncoder()
                .encodeToString(ByteBuffer
                        .allocate(salt.length + encryptedSPK.length)
                        .put(salt)
                        .put(encryptedSPK)
                        .array());

        blindnetClient.sendPrivateKeys(encryptedEKPBase64, encryptedSKPBase64);
    }

    /**
     * Retrieves user's private keys from Blindnet API and decrypts them.
     *
     * @param password a password phrase used for decryption.
     */
    @Override
    public void decrypt(String password) {

        PrivateKeyPair privateKeyPair = blindnetClient.fetchPrivateKeys();

        ByteBuffer encryptedEPKWithSalt = ByteBuffer.wrap(Base64.getUrlDecoder()
                .decode(privateKeyPair.getEncryptionKey()));

        byte[] salt = new byte[SALT_LENGTH];
        encryptedEPKWithSalt.get(salt);

        byte[] encryptedEPK = new byte[encryptedEPKWithSalt.remaining()];
        encryptedEPKWithSalt.get(encryptedEPK);

        ByteBuffer encryptedSPKWithSalt = ByteBuffer.wrap(Base64.getUrlDecoder()
                .decode(privateKeyPair.getSigningKey()));

        int encryptedSPKLength = encryptedSPKWithSalt.array().length - SALT_LENGTH;
        byte[] encryptedSPK = new byte[encryptedSPKLength];
        encryptedSPKWithSalt.get(encryptedSPK, SALT_LENGTH, encryptedSPKLength);

        SecretKey secretKey = keyFactory.getAESKeyFromPassword(password.toCharArray(),
                salt,
                PBKDF_SHA256);

        byte[] encryptionPK = encryptionService.decrypt(secretKey, encryptedEPK);
        byte[] signingPK = encryptionService.decrypt(secretKey, encryptedSPK);

        keyStorage.storeEncryptionKey(keyFactory.convertToPrivateKey(encryptionPK, RSA_ALGORITHM));
        keyStorage.storeSigningKey(keyFactory.convertToPrivateKey(signingPK, ECDSA_ALGORITHM));
    }

}
