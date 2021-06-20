package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.internal.JwtConfig;
import io.blindnet.blindnet.internal.KeyFactory;
import io.blindnet.blindnet.internal.KeyStorage;
import io.blindnet.blindnet.internal.SigningService;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static io.blindnet.blindnet.internal.EncryptionConstants.Ed25519_ALGORITHM;
import static java.util.Objects.requireNonNull;

public class UserSignalServiceImpl implements UserSignalService {

    private final KeyStorage keyStorage;
    private final KeyFactory keyFactory;
    private final SigningService signingService;
    private final SignalApiClient signalApiClient;
    private final JwtConfig jwtConfig;

    UserSignalServiceImpl(KeyStorage keyStorage,
                          KeyFactory keyFactory,
                          SigningService signingService,
                          SignalApiClient signalApiClient) {

        this.keyStorage = keyStorage;
        this.keyFactory = keyFactory;
        this.signingService = signingService;
        this.signalApiClient = signalApiClient;
        this.jwtConfig = JwtConfig.INSTANCE;
    }

    @Override
    public UserRegistrationResult register() {
        // generate pre keys
        KeyPair identityKeyPair = keyFactory.generateEd25519KeyPair();
        PrivateKey identityPrivateKey = identityKeyPair.getPrivate();
        String identityKeyPairID = UUID.randomUUID().toString();

        KeyPair preKeyPair = keyFactory.generateEd25519KeyPair();
        String preKeyPairID = UUID.randomUUID().toString();

        Map<String, KeyPair> preKeyPairs = new HashMap<>();
        for (int i = 0; i < 10; i++) {
            preKeyPairs.put(UUID.randomUUID().toString(), keyFactory.generateEd25519KeyPair());
        }

        // generate device id and store it
        String deviceID = UUID.randomUUID().toString();
        keyStorage.storeDeviceID(deviceID);

        // store private keys
        keyStorage.storeEd25519PrivateKey(identityPrivateKey, identityKeyPairID);
        keyStorage.storeEd25519PrivateKey(preKeyPair.getPrivate(), preKeyPairID);
        preKeyPairs.keySet().forEach(key -> keyStorage.storeEd25519PrivateKey(preKeyPairs.get(key).getPrivate(), key));

        // signs jwt with private identity key
        byte[] signedJwt = signingService.sign(requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."),
                identityPrivateKey,
                Ed25519_ALGORITHM);

        byte[] publicIdentityKeyEncoded = keyFactory.encodeEd25519PublicKey(identityKeyPair.getPublic());

        Base64.Encoder encoder = Base64.getEncoder();
        byte[] preKeyEncoded = keyFactory.encodeEd25519PublicKey(preKeyPair.getPublic());
        // signs public pre key with private identity key
        byte[] signedPublicPreKey = signingService.sign(preKeyEncoded,
                identityPrivateKey,
                Ed25519_ALGORITHM);

        Map<String, String> listOfPublicPreKeys = new HashMap<>();
        preKeyPairs.keySet().forEach(key ->
                listOfPublicPreKeys.put(key, encoder.encodeToString(keyFactory.encodeEd25519PublicKey(preKeyPairs.get(key).getPublic()))));

        // sends a request to the blindnet api
        return signalApiClient.register(jwtConfig.getJwt(),
                deviceID,
                encoder.encodeToString(publicIdentityKeyEncoded),
                identityKeyPairID,
                encoder.encodeToString(preKeyEncoded),
                preKeyPairID,
                encoder.encodeToString(signedPublicPreKey),
                listOfPublicPreKeys,
                Base64.getUrlEncoder().encodeToString(signedJwt)
        );
    }

    @Override
    public void unregister() {
        signalApiClient.unregister();
        keyStorage.deleteKeyFolder();
    }

}
