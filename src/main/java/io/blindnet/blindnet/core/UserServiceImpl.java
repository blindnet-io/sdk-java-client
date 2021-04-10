package io.blindnet.blindnet.core;

import io.blindnet.blindnet.UserService;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.logging.Logger;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;

class UserServiceImpl implements UserService {

    private static final Logger LOGGER = Logger.getLogger(UserServiceImpl.class.getName());

    // TODO: FR-SDK03; exposed
    @Override
    public String register(String jwt) throws GeneralSecurityException, IOException {
        // generate encryption key pair
        KeyPair encryptionKeyPair = KeyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE);
        PrivateKey encryptionPrivateKey = encryptionKeyPair.getPrivate();

        //generate signing key pair
        KeyPair signingKeyPair = KeyFactory.generateKeyPair(ECDSA_ALGORITHM, BC_PROVIDER, SECRP_256_R_CURVE);
        PrivateKey signingPrivateKey = signingKeyPair.getPrivate();

        // store encryption and signing private key
        // todo set this as class level field ?
        KeyStorage keyStorage = new KeyStorage();
        System.out.println("Writing encryption key");
        keyStorage.storeEncryptionKey(encryptionPrivateKey);
        System.out.println("Writing signing key");
        keyStorage.storeSigningKey(signingPrivateKey);

        // signs jwt with private key
        // todo set this as class level field ?
        SigningService signingService = new SigningService();
        String signedJwt = signingService.sign(jwt, signingPrivateKey, SHA_256_ECDSA_ALGORITHM);

        // sends register request to the blind net api
        // todo set this as class level field ?
        BlindnetClient blindnetClient = new BlindnetClient();
        // receives registration confirmation
        blindnetClient.register(jwt, encryptionKeyPair.getPublic(), signingKeyPair.getPublic(), signedJwt);

        return "";
    }

}
