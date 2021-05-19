package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.exception.KeyConstructionException;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;

import static io.blindnet.blindnet.core.EncryptionConstants.*;
import static java.util.Objects.requireNonNull;

/**
 * Default implementation of user service.
 */
class UserServiceImpl implements UserService {

    private final KeyStorage keyStorage;
    private final KeyFactory keyFactory;
    private final SigningService signingService;
    private final ApiClient apiClient;
    private final JwtConfig jwtConfig;

    UserServiceImpl(KeyStorage keyStorage,
                    KeyFactory keyFactory,
                    SigningService signingService,
                    ApiClient apiClient) {

        this.keyStorage = keyStorage;
        this.keyFactory = keyFactory;
        this.signingService = signingService;
        this.apiClient = apiClient;
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

        byte[] publicSigningKeyEncodedWithoutPrefix = Arrays.copyOfRange(
                signingKeyPair.getPublic().getEncoded(), 12, signingKeyPair.getPublic().getEncoded().length);

        Base64.Encoder encoder = Base64.getEncoder();
        try {
            SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
                    encryptionKeyPair.getPublic().getEncoded());
            byte[] signedEncryptionPublicKey = signingService.sign(publicKeyInfo.getEncoded(),
                    signingPrivateKey,
                    Ed25519_ALGORITHM);

            return apiClient.register(encoder.encodeToString(publicKeyInfo.getEncoded()),
                    encoder.encodeToString(signedEncryptionPublicKey),
                    encoder.encodeToString(publicSigningKeyEncodedWithoutPrefix),
                    Base64.getUrlEncoder().encodeToString(signedJwt));
        } catch (IOException e) {
            throw new KeyConstructionException("Unable to convert public key to SPKI format.");
        }
    }

    /**
     * Unregisters a user using Blindnet API and deletes his local data.
     */
    public void unregister() {
        apiClient.unregister();
        keyStorage.deleteKeyFolder();
    }

}
