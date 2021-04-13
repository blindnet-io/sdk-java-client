package io.blindnet.blindnet.core;

import io.blindnet.blindnet.UserService;

import java.io.IOException;
import java.security.GeneralSecurityException;
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
    // TODO: FR-SDK03; exposed
    // TODO: define return value
    @Override
    public String register(String jwt) {
        // generate encryption key pair
        KeyPair encryptionKeyPair = KeyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        PrivateKey encryptionPrivateKey = encryptionKeyPair.getPrivate();

        //generate signing key pair
        KeyPair signingKeyPair = KeyFactory.generateKeyPair(ECDSA_ALGORITHM, BC_PROVIDER, SECRP_256_R_CURVE);
        PrivateKey signingPrivateKey = signingKeyPair.getPrivate();

        // store encryption and signing private key
        System.out.println("Writing encryption key");
        keyStorage.storeEncryptionKey(encryptionPrivateKey);
        System.out.println("Writing signing key");
        keyStorage.storeSigningKey(signingPrivateKey);

        // signs jwt with private key
        String signedJwt = signingService.sign(jwt, signingPrivateKey, SHA_256_ECDSA_ALGORITHM);

        // sends register request to the blind net api
        // receives registration confirmation
        blindnetClient.register(jwt, encryptionKeyPair.getPublic(), signingKeyPair.getPublic(), signedJwt);

        return "";
    }

}
