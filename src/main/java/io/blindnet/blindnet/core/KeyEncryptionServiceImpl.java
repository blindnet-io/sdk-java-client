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

        SecretKey secretKey = keyFactory.extractAesKeyFromPassword(password.toCharArray(),
                salt,
                PBKDF_SHA256);

        PrivateKey encryptionPrivateKey = keyStorage.readEncryptionPrivateKey();
        PrivateKey signingPrivateKey = keyStorage.readSigningPrivateKey();

        byte[] encryptedEPK = encryptionService.encrypt(secretKey, encryptionPrivateKey.getEncoded());
        byte[] encryptedSPK = encryptionService.encrypt(secretKey, signingPrivateKey.getEncoded());

        blindnetClient.sendPrivateKeys(Base64.getUrlEncoder().encodeToString(encryptedEPK),
                Base64.getUrlEncoder().encodeToString(encryptedSPK),
                Base64.getUrlEncoder().encodeToString(salt));
    }

    /**
     * Retrieves user's private keys from Blindnet API and decrypts them.
     *
     * @param password a password phrase used for decryption.
     */
    @Override
    public void decrypt(String password) {
        PrivateKeyPair privateKeyPair = blindnetClient.fetchPrivateKeys();

        byte[] salt = Base64.getUrlDecoder().decode(privateKeyPair.getKeyDerivationSalt());
        byte[] encryptedEPK = Base64.getUrlDecoder().decode(privateKeyPair.getEncryptionKey());
        byte[] encryptedSPK = Base64.getUrlDecoder().decode(privateKeyPair.getEncryptionKey());

        SecretKey secretKey = keyFactory.extractAesKeyFromPassword(password.toCharArray(),
                salt,
                PBKDF_SHA256);

        byte[] encryptionPK = encryptionService.decrypt(secretKey, encryptedEPK);
        byte[] signingPK = encryptionService.decrypt(secretKey, encryptedSPK);

        keyStorage.storeEncryptionKey(keyFactory.convertToPrivateKey(encryptionPK, RSA_ALGORITHM));
        keyStorage.storeSigningKey(keyFactory.convertToPrivateKey(signingPK, Ed25519_ALGORITHM));
    }

}
