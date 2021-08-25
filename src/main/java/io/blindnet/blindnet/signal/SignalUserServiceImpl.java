package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.exception.UnregisterException;
import io.blindnet.blindnet.internal.*;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

import java.io.File;
import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

import static io.blindnet.blindnet.internal.DatabaseConfig.DATABASE_NAME;
import static io.blindnet.blindnet.internal.EncryptionConstants.Ed25519_ALGORITHM;
import static java.util.Objects.requireNonNull;

public class SignalUserServiceImpl implements SignalUserService {

    private final KeyFactory keyFactory;
    private final SignalIdentityKeyStore signalIdentityKeyStore;
    private final SignalPreKeyStore signalPreKeyStore;
    private final SignalSignedPreKeyStore signalSignedPreKeyStore;
    private final SigningService signingService;
    private final SignalApiClient signalApiClient;
    private final JwtConfig jwtConfig;
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
        this.jwtConfig = JwtConfig.INSTANCE;
        this.signalIdentityKeyStore = signalIdentityKeyStore;
        this.signalSignedPreKeyStore = signalSignedPreKeyStore;
        this.signalPreKeyStore = signalPreKeyStore;
    }

    public UserRegistrationResult register() throws InvalidKeyException {
        // generate device id, identity key pair, identity key pair id (registration id) and store them
        int deviceId = ThreadLocalRandom.current().nextInt();
        IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
        int registrationId = KeyHelper.generateRegistrationId(false);
        signalIdentityKeyStore.saveLocalIdentity(registrationId, deviceId, identityKeyPair);

        // generate pre key pair, sign it using identity key pair and store it
        SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, ThreadLocalRandom.current().nextInt());
        signalSignedPreKeyStore.storeSignedPreKey(signedPreKey.getId(), signedPreKey);

        //generate set of ten pre key pairs
        int startId = ThreadLocalRandom.current().nextInt();
        List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(startId, 10);
        preKeys.forEach(preKey -> signalPreKeyStore.storePreKey(preKey.getId(), preKey));

        // signs jwt with private identity key
        KeyPair signingKeyPair = keyFactory.generateEd25519KeyPair();
        byte[] signedJwt = signingService.sign(requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."),
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
                Base64.getUrlEncoder().encodeToString(signedJwt)
        );
    }

    @Override
    public void unregister() {
        signalApiClient.unregister();
        File db = new File(DatabaseConfig.INSTANCE.getDbPath() + DATABASE_NAME);
        if (!db.delete()) {
            throw new UnregisterException("Unable to clear user data.");
        }
    }

}
