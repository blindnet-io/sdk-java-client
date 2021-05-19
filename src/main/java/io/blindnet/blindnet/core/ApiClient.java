package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.*;
import io.blindnet.blindnet.exception.SignatureException;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;

import static io.blindnet.blindnet.core.ApiClientConstants.*;
import static io.blindnet.blindnet.core.EncryptionConstants.*;
import static java.util.Objects.requireNonNull;

/**
 * Provides API for communication with Blindnet API.
 */
class ApiClient {

    private final KeyStorage keyStorage;
    private final KeyFactory keyFactory;
    private final EncryptionService encryptionService;
    private final HttpClient httpClient;
    private final KeyEnvelopeService keyEnvelopeService;
    private final JwtConfig jwtConfig;

    public ApiClient(KeyStorage keyStorage,
                     KeyFactory keyFactory,
                     EncryptionService encryptionService,
                     HttpClient httpClient,
                     KeyEnvelopeService keyEnvelopeService) {

        this.keyStorage = keyStorage;
        this.keyFactory = keyFactory;
        this.encryptionService = encryptionService;
        this.httpClient = httpClient;
        this.keyEnvelopeService = keyEnvelopeService;
        this.jwtConfig = JwtConfig.INSTANCE;
    }

    /**
     * Registers user against Blindnet API.
     *
     * @param publicEncryptionKey       user's public key used for encryption.
     * @param signedPublicEncryptionKey a signature of public key used for encryption.
     * @param publicSigningKey          user's public key used for signing.
     * @param signedJwt                 a JWT signature.
     * @return a user registration result object.
     */
    public UserRegistrationResult register(String publicEncryptionKey,
                                           String signedPublicEncryptionKey,
                                           String publicSigningKey,
                                           String signedJwt) {
        requireNonNull(publicEncryptionKey, "Public Encryption Key cannot be null.");
        requireNonNull(signedPublicEncryptionKey, "Signed Public Encryption Key cannot be null.");
        requireNonNull(publicSigningKey, "Public Signing Key cannot be null.");
        requireNonNull(signedJwt, "Signed JWT cannot be null.");

        JSONObject requestBody = new JSONObject().put("publicEncryptionKey", publicEncryptionKey)
                .put("publicSigningKey", publicSigningKey)
                .put("signedPublicEncryptionKey", signedPublicEncryptionKey)
                .put("signedJwt", signedJwt);

        HttpResponse httpResponse = httpClient.post(ApiConfig.INSTANCE.getServerUrl() + USER_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."),
                requestBody.toString().getBytes(StandardCharsets.UTF_8));

        return new UserRegistrationResult(httpResponse.getStatus() == HttpURLConnection.HTTP_OK, httpResponse.getMessage());
    }

    /**
     * Unregisters a user from Blindnet API.
     */
    public void unregister() {
        httpClient.delete(ApiConfig.INSTANCE.getServerUrl() + DELETE_USER_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));
    }

    /**
     * Sends a Secret Key of a user doubly encrypted and wrapped into an Envelop object,
     *
     * @param senderKeyEnvelope    an envelop object which contains a user's secret key encrypted using sender's key.
     * @param recipientKeyEnvelope an envelop object which contains a user's secret key encrypted using recipient's key.
     */
    public void sendSecretKey(KeyEnvelope senderKeyEnvelope, KeyEnvelope recipientKeyEnvelope) {
        requireNonNull(senderKeyEnvelope, "Sender Key Envelope cannot be null");
        requireNonNull(recipientKeyEnvelope, "Recipient Key Envelope cannot be null");

        JSONArray requestBody = new JSONArray().put(new JSONObject(recipientKeyEnvelope))
                .put(new JSONObject(senderKeyEnvelope));

        httpClient.post(ApiConfig.INSTANCE.getServerUrl() + SYMMETRIC_KEY_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."),
                requestBody.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Fetches a Secret Key of a user from Blindnet API and validates a signature of an Envelope.
     *
     * @param senderId    an id of the sender.
     * @param recipientId an id of the recipient.
     * @return a secret key object.
     */
    public SecretKey fetchSecretKey(String senderId, String recipientId) {
        requireNonNull(senderId, "Sender ID cannot be null.");
        requireNonNull(recipientId, "Recipient ID cannot be null.");

        HttpResponse httpResponse = httpClient.get(ApiConfig.INSTANCE.getServerUrl() + SYMMETRIC_KEY_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));

        JSONObject responseBody = new JSONObject(new String(httpResponse.getBody()));
        KeyEnvelope keyEnvelope = new KeyEnvelope.Builder(responseBody.getString("envelopeID"))
                .withEncryptedSymmetricKey(responseBody.getString("key"))
                .withKeyOwnerID(responseBody.getString("ownerID"))
                .withRecipientID(responseBody.getString("recipientID"))
                .withSenderID(responseBody.getString("senderID"))
                .withVersion(responseBody.getString("envelopeVersion"))
                .timestamp(responseBody.getString("timestamp"))
                .build();

        // use local signing public key if the current user is not recipient otherwise pull it from blindnet api
        PublicKey signingKey = JwtUtil.extractUserId(jwtConfig.getJwt()).equals(recipientId) ?
                fetchPublicKeys(senderId).getSigningKey() :
                ((EdDSAPrivateKey) keyStorage.readSigningPrivateKey()).getPublicKey();

        String keyEnvelopeSignature = responseBody.getString("envelopeSignature");
        if (!keyEnvelopeService.verify(keyEnvelope, keyEnvelopeSignature, signingKey)) {
            throw new SignatureException("Unable to verify key envelope signature.");
        }

        byte[] keyData = (byte[]) new JSONObject(encryptionService.decrypt(keyStorage.readEncryptionPrivateKey(),
                Base64.getDecoder().decode(keyEnvelope.getEncryptedSymmetricKey()))).get("k");

        return new SecretKeySpec(keyData, 0, keyData.length, AES_ALGORITHM);
    }

    /**
     * Sends encrypted signing and encryption private keys of a user to the Blindnet API.
     *
     * @param encryptedPrivateEncryptionKey a encrypted private key object used for encryption.
     * @param encryptedPrivateSigningKey    a encrypted private key object used for signing.
     * @param salt                          a key derivation salt used to generate secret encryption key.
     */
    public void sendPrivateKeys(String encryptedPrivateEncryptionKey,
                                String encryptedPrivateSigningKey,
                                String salt) {

        requireNonNull(encryptedPrivateEncryptionKey, "Encryption Private Key cannot be null.");
        requireNonNull(encryptedPrivateSigningKey, "Signing Private Key cannot be null.");

        JSONObject requestBody = new JSONObject().put("encryptedPrivateEncryptionKey", encryptedPrivateEncryptionKey)
                .put("encryptedPrivateSigningKey", encryptedPrivateSigningKey)
                .put("keyDerivationSalt", salt);

        httpClient.put(ApiConfig.INSTANCE.getServerUrl() + PRIVATE_KEYS_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."),
                requestBody.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Fetches encrypted signing and encryption private keys of a user from Blindnet API.
     *
     * @return a private key pair object.
     */
    public PrivateKeys fetchPrivateKeys() {
        HttpResponse httpResponse = httpClient.get(ApiConfig.INSTANCE.getServerUrl() + PRIVATE_KEYS_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));

        JSONObject responseBody = new JSONObject(new String(httpResponse.getBody()));
        return new PrivateKeys(responseBody.getString("encryptedPrivateEncryptionKey"),
                responseBody.getString("encryptedPrivateSigningKey"),
                responseBody.getString("keyDerivationSalt"));
    }

    /**
     * Fetches encryption and signing public keys of a user from Blindnet API.
     *
     * @param recipientId an id of a user whose keys are requested,
     * @return a public key pair object.
     */
    public PublicKeys fetchPublicKeys(String recipientId) {
        requireNonNull(recipientId, "Recipient ID cannot be null.");

        HttpResponse httpResponse = httpClient.get(ApiConfig.INSTANCE.getServerUrl() + FETCH_PUBLIC_KEYS_ENDPOINT_PATH + recipientId,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));

        JSONObject responseBody = new JSONObject(new String(httpResponse.getBody()));
        PublicKey encryptionKey = keyFactory.convertToPublicKey(
                responseBody.getString("publicEncryptionKey"),
                RSA_ALGORITHM);
        PublicKey signingKey = keyFactory.convertToPublicKey(
                responseBody.getString("publicSigningKey"),
                Ed25519_ALGORITHM);
        String signedPublicEncryptionKey = responseBody.getString("signedPublicEncryptionKey");

        return new PublicKeys(encryptionKey, signingKey, signedPublicEncryptionKey);
    }

}
