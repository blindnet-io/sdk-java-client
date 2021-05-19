package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.PrivateKeys;
import io.blindnet.blindnet.domain.RsaJwk;
import org.json.JSONObject;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.util.Base64;

import static io.blindnet.blindnet.core.EncryptionConstants.*;

/**
 * Default implementation of key encryption service.
 */
class KeyEncryptionServiceImpl implements KeyEncryptionService {

    private final KeyStorage keyStorage;
    private final KeyFactory keyFactory;
    private final EncryptionService encryptionService;
    private final ApiClient apiClient;

    public KeyEncryptionServiceImpl(KeyStorage keyStorage,
                                    KeyFactory keyFactory,
                                    EncryptionService encryptionService,
                                    ApiClient apiClient) {

        this.keyStorage = keyStorage;
        this.keyFactory = keyFactory;
        this.encryptionService = encryptionService;
        this.apiClient = apiClient;
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

        byte[] encryptedEPK = encryptionService.encrypt(secretKey,
                new JSONObject(new RsaJwk(encryptionPrivateKey)).toString().getBytes());
        byte[] encryptedSPK = encryptionService.encrypt(secretKey, signingPrivateKey.getEncoded());

        Base64.Encoder encoder = Base64.getEncoder();
        apiClient.sendPrivateKeys(encoder.encodeToString(encryptedEPK),
                encoder.encodeToString(encryptedSPK),
                encoder.encodeToString(salt));
    }

    /**
     * Retrieves user's private keys from Blindnet API and decrypts them.
     *
     * @param password a password phrase used for decryption.
     */
    @Override
    public void decrypt(String password) {
        PrivateKeys privateKeys = apiClient.fetchPrivateKeys();

        Base64.Decoder decoder = Base64.getDecoder();
        byte[] salt = decoder.decode(privateKeys.getKeyDerivationSalt());
        byte[] encryptedEPK = decoder.decode(privateKeys.getEncryptionKey());
        byte[] encryptedSPK = decoder.decode(privateKeys.getEncryptionKey());

        SecretKey secretKey = keyFactory.extractAesKeyFromPassword(password.toCharArray(),
                salt,
                PBKDF_SHA256);

        keyStorage.storeEncryptionKey(keyFactory.convertToRsaPrivateKey(
                new JSONObject(new String(encryptionService.decrypt(secretKey, encryptedEPK)))));
        keyStorage.storeSigningKey(keyFactory.convertToEd25519PrivateKey(
                encryptionService.decrypt(secretKey, encryptedSPK)));
    }

}
