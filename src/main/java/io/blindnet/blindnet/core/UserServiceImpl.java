package io.blindnet.blindnet.core;

import io.blindnet.blindnet.UserService;
import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.exception.KeyStorageException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;

/**
 * Provides API to handle User related operations.
 *
 * @author stefanveselinovic
 */
class UserServiceImpl implements UserService {

    private static final Logger LOGGER = Logger.getLogger(UserServiceImpl.class.getName());

    private KeyStorage keyStorage;
    private JwtService jwtService;
    private BlindnetClient blindnetClient;

    UserServiceImpl(KeyStorage keyStorage, JwtService jwtService, BlindnetClient blindnetClient) {
        // todo to be changed
        this.keyStorage = keyStorage;
        this.jwtService = jwtService;
        this.blindnetClient = blindnetClient;
    }

    /**
     * Registers a user using Blindnet API.
     *
     * @param jwt JWT representing a user that will be registered.
     * @return tbd
     */
    @Override
    public UserRegistrationResult register(String jwt) {
        KeyPair encryptionKeyPair = KeyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        PrivateKey encryptionPrivateKey = encryptionKeyPair.getPrivate();
        keyStorage.storeEncryptionKey(encryptionPrivateKey);

        KeyPair signingKeyPair = KeyFactory.generateKeyPair(ECDSA_ALGORITHM, BC_PROVIDER, SECRP_256_R_CURVE);
        PrivateKey signingPrivateKey = signingKeyPair.getPrivate();
        keyStorage.storeSigningKey(signingPrivateKey);

        String signedJwt = jwtService.sign(jwt, signingPrivateKey, SHA_256_ECDSA_ALGORITHM);

        return blindnetClient.register(jwt, encryptionKeyPair.getPublic(), signingKeyPair.getPublic(), signedJwt);
    }

    /**
     * Unregisters a user using Blindnet API and deletes his local data.
     *
     * @param jwt a JWT representing a user which will be deleted.
     */
    public void unregister(String jwt) {
        blindnetClient.unregister(jwt);

        if (!keyStorage.deleteSigningKey()) {
            String msg = "Unable to delete local signing key.";
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyStorageException(msg);
        }
        if (!keyStorage.deleteEncryptionKey()) {
            String msg = "Unable to delete local encryption key.";
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyStorageException(msg);
        }
    }

}
