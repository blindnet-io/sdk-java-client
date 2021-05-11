package io.blindnet.blindnet.core;

import io.blindnet.blindnet.UserService;
import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.exception.KeyStorageException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
import static java.util.Objects.requireNonNull;

/**
 * Provides API to handle User related operations.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
class UserServiceImpl implements UserService {

    private static final Logger LOGGER = Logger.getLogger(UserServiceImpl.class.getName());

    private final KeyStorage keyStorage;
    private final KeyFactory keyFactory;
    private final SigningService signingService;
    private final BlindnetClient blindnetClient;
    private final JwtConfig jwtConfig;

    UserServiceImpl(KeyStorage keyStorage,
                    KeyFactory keyFactory,
                    SigningService signingService,
                    BlindnetClient blindnetClient) {

        this.keyStorage = keyStorage;
        this.keyFactory = keyFactory;
        this.signingService = signingService;
        this.blindnetClient = blindnetClient;
        this.jwtConfig = JwtConfig.INSTANCE;
    }

    /**
     * Registers a user using Blindnet API.
     *
     * @return a user registration result object.
     */
    @Override
    public UserRegistrationResult register() {
        KeyPair encryptionKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        PrivateKey encryptionPrivateKey = encryptionKeyPair.getPrivate();
        keyStorage.storeEncryptionKey(encryptionPrivateKey);

        KeyPair signingKeyPair = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);
        PrivateKey signingPrivateKey = signingKeyPair.getPrivate();
        keyStorage.storeSigningKey(signingPrivateKey);

        byte[] signedJwt = signingService.sign(requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."),
                signingPrivateKey,
                Ed25519_ALGORITHM);

        byte[] signedEncryptionPublicKey = signingService.sign(encryptionKeyPair.getPublic(),
                signingPrivateKey,
                Ed25519_ALGORITHM);

        byte[] publicSigningKeyEncodedWithoutPrefix = Arrays.copyOfRange(
                signingKeyPair.getPublic().getEncoded(), 12, signingKeyPair.getPublic().getEncoded().length);

        Base64.Encoder encoder = Base64.getEncoder();
        return blindnetClient.register(encoder.encodeToString(encryptionKeyPair.getPublic().getEncoded()),
                encoder.encodeToString(signedEncryptionPublicKey),
                encoder.encodeToString(publicSigningKeyEncodedWithoutPrefix),
                Base64.getUrlEncoder().encodeToString(signedJwt));
    }

    /**
     * Unregisters a user using Blindnet API and deletes his local data.
     */
    public void unregister() {
        blindnetClient.unregister();

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
        if (!keyStorage.deleteRecipientSigningPublicKeys()) {
            String msg = "Unable to delete all public signing keys of recipients.";
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyStorageException(msg);
        }
    }

}
