package io.blindnet.blindnet.core;

import io.blindnet.blindnet.KeyEncryptionService;
import io.blindnet.blindnet.domain.PrivateKeyPair;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;

public class KeyEncryptionServiceImpl implements KeyEncryptionService {

    private EncryptionService encryptionService;
    private KeyStorage keyStorage;
    private BlindnetClient blindnetClient;

    public KeyEncryptionServiceImpl() {
        encryptionService = new EncryptionService();
        keyStorage = new KeyStorage();
        blindnetClient = new BlindnetClient();
    }

    // TODO FR012

    /**
     * todo javadoc
     *
     * @param jwt
     * @param password
     */
    @Override
    public void encrypt(String jwt, String password) {
        try {

            byte[] salt = KeyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, SALT_LENGTH);

            SecretKey secretKey = KeyFactory.getAESKeyFromPassword(password.toCharArray(),
                    salt,
                    PBKDF_SHA256,
                    AES_ALGORITHM,
                    AES_KEY_SIZE,
                    AES_KEY_ITERATION_COUNT);

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

            blindnetClient.sendPrivateKeys(jwt, encryptedEKPBase64, encryptedSKPBase64);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException exception) {
            System.out.println("err");
        }
    }

    // TODO FR013

    /**
     * todo javadoc
     *
     * @param jwt
     * @param password
     */
    @Override
    public void decrypt(String jwt, String password) {

        try {
            PrivateKeyPair privateKeyPair = blindnetClient.fetchPrivateKeys(jwt);

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

            SecretKey secretKey = KeyFactory.getAESKeyFromPassword(password.toCharArray(),
                    salt,
                    PBKDF_SHA256,
                    AES_ALGORITHM,
                    AES_KEY_SIZE,
                    AES_KEY_ITERATION_COUNT);

            byte[] encryptionPK = encryptionService.decrypt(secretKey, encryptedEPK);
            byte[] signingPK = encryptionService.decrypt(secretKey, encryptedSPK);

            keyStorage.storeEncryptionKey(KeyFactory.convertToPrivateKey(encryptionPK, RSA_ALGORITHM));
            keyStorage.storeSigningKey(KeyFactory.convertToPrivateKey(signingPK, ECDSA_ALGORITHM));

        } catch (NoSuchAlgorithmException | InvalidKeySpecException exception) {
            System.out.println("err");
        }

    }
}
