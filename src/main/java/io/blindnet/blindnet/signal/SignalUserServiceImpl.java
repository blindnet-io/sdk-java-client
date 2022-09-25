package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.exception.UserRegistrationException;
import io.blindnet.blindnet.internal.*;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

import java.io.File;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.blindnet.blindnet.internal.DatabaseConfig.DATABASE_NAME;
import static io.blindnet.blindnet.internal.EncryptionConstants.Ed25519_ALGORITHM;
import static java.util.Objects.requireNonNull;

/**
 * Implementation of service that provides API to register/unregister user against Signal Blindnet API.
 */
class SignalUserServiceImpl implements SignalUserService {

    private final KeyFactory keyFactory;
    private final SignalIdentityKeyStore signalIdentityKeyStore;
    private final SignalPreKeyStore signalPreKeyStore;
    private final SignalSignedPreKeyStore signalSignedPreKeyStore;
    private final SigningService signingService;
    private final SignalApiClient signalApiClient;
    private final TokenConfig tokenConfig;
    private final SignalKeyFactory signalKeyFactory;

    SignalUserServiceImpl(KeyFactory keyFactory,
                          SignalKeyFactory signalKeyFactory,
                          SigningService signingService,
                          SignalApiClient signalApiClient,
                          SignalIdentityKeyStore signalIdentityKeyStore,
                          SignalSignedPreKeyStore signalSignedPreKeyStore,
                          SignalPreKeyStore signalPreKeyStore) {

        this.keyFactory = keyFactory;
        this.signalKeyFactory = signalKeyFactory;
        this.signingService = signingService;
        this.signalApiClient = signalApiClient;
        this.tokenConfig = TokenConfig.INSTANCE;
        this.signalIdentityKeyStore = signalIdentityKeyStore;
        this.signalSignedPreKeyStore = signalSignedPreKeyStore;
        this.signalPreKeyStore = signalPreKeyStore;
    }

    /**
     * Registers a Signal user using Blindnet API.
     *
     * @return a Signal user registration result object.
     */
    public UserRegistrationResult register() {
        // generate device id, identity key pair, identity key pair id (registration id) and store them
        int deviceId = new SecureRandom().nextInt(Integer.MAX_VALUE);
        IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
        int registrationId = KeyHelper.generateRegistrationId(false);
        signalIdentityKeyStore.saveLocalIdentity(registrationId, deviceId, identityKeyPair);

        // generate pre key pair, sign it using identity key pair and store it
        SignedPreKeyRecord signedPreKey;
        try {
            signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, new SecureRandom().nextInt());
            signalSignedPreKeyStore.storeSignedPreKey(signedPreKey.getId(), signedPreKey);
        } catch (InvalidKeyException exception) {
            throw new UserRegistrationException("Error: Unable to register user. Signing pre key failed.");
        }

        //generate set of ten pre key pairs
        int startId = new SecureRandom().nextInt();
        List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(startId, 10);
        preKeys.forEach(preKey -> signalPreKeyStore.storePreKey(preKey.getId(), preKey));

        // signs token with private identity key
        KeyPair signingKeyPair = keyFactory.generateEd25519KeyPair();
        byte[] signedToken = signingService.sign(requireNonNull(tokenConfig.getToken(), "Token not configured properly."),
                signingKeyPair.getPrivate(),
                Ed25519_ALGORITHM);

        Base64.Encoder encoder = Base64.getEncoder();

        Map<String, String> listOfPublicPreKeys = new HashMap<>();
        preKeys.forEach(key ->
                listOfPublicPreKeys.put(String.valueOf(key.getId()), encoder.encodeToString(
                        signalKeyFactory.removeKeyTypeByte(key.getKeyPair().getPublicKey().serialize()))));

        // sends a request to the blindnet api
        return signalApiClient.register(String.valueOf(deviceId),
                encoder.encodeToString(keyFactory.encodeEd25519PublicKey(signingKeyPair.getPublic())),
                encoder.encodeToString(signalKeyFactory.removeKeyTypeByte(identityKeyPair.getPublicKey().serialize())),
                String.valueOf(registrationId),
                encoder.encodeToString(signalKeyFactory.removeKeyTypeByte(signedPreKey.getKeyPair().getPublicKey().serialize())),
                String.valueOf(signedPreKey.getId()),
                encoder.encodeToString(signedPreKey.getSignature()),
                listOfPublicPreKeys,
                Base64.getUrlEncoder().encodeToString(signedToken)
        );
    }

    /**
     * Unregisters a Signal user using Blindnet API and deletes his local data.
     */
    @Override
    public void unregister() {
        signalApiClient.unregister();
        File db = new File(DatabaseConfig.INSTANCE.getDbPath() + DATABASE_NAME);
        if (!db.delete()) {
            throw new UserRegistrationException("Unable to clear local user data.");
        }
    }

}
