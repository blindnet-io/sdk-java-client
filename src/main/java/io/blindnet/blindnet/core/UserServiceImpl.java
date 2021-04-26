package io.blindnet.blindnet.core;

import io.blindnet.blindnet.UserService;
import io.blindnet.blindnet.domain.UserRegistrationResult;

import java.security.KeyPair;
import java.security.PrivateKey;
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
    private JwtService signingService;
    private BlindnetClient blindnetClient;

    UserServiceImpl(KeyStorage keyStorage, JwtService signingService, BlindnetClient blindnetClient) {
        this.keyStorage = keyStorage;
        this.signingService = signingService;
        this.blindnetClient = blindnetClient;
    }

    /**
     * Registers user using blindnet API.
     *
     * @param jwt JWT representing a user that will be registered against blindnet API.
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

        String signedJwt = signingService.sign(jwt, signingPrivateKey, SHA_256_ECDSA_ALGORITHM);

        return blindnetClient.register(jwt, encryptionKeyPair.getPublic(), signingKeyPair.getPublic(), signedJwt);
    }

    /**
     * todo add javadoc
     *
     * @param jwt
     */
    // todo FR13
    public void unregister(String jwt) {
        // todo 1. delete user private keys
        // todo 2. send request to blindnet api to delete user
    }

}
