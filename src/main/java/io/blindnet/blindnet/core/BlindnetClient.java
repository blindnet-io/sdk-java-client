package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.*;
import io.blindnet.blindnet.exception.SignatureException;
import org.json.JSONObject;

import javax.crypto.SecretKey;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
import static java.util.Objects.requireNonNull;

/**
 * Provides API for communication with Blindnet API.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
class BlindnetClient {

    private static final Logger LOGGER = Logger.getLogger(BlindnetClient.class.getName());

    // todo check if the server url should be configured
    private static final String BLINDNET_SERVER_URL = "https://9e8f8063-e45a-4046-a88d-c7a8a14a5cb2.mock.pstmn.io";
    // private static final String BLINDNET_SERVER_URL = "https://4134cf66-97a3-418a-a189-3363113b99f1.mock.pstmn.io";
    // private static final String BLINDNET_SERVER_URL = "https://38d53445-1473-4da0-9ab6-f34a24412c93.mock.pstmn.io";
    private static final String USER_ENDPOINT_PATH = "/api/v1/users";
    private static final String FETCH_SYMMETRIC_KEY_ENDPOINT_PATH = "/api/v1/old/users";
    private static final String SEND_SYMMETRIC_KEY_ENDPOINT_PATH = "/api/v1/old/users";
    private static final String PRIVATE_KEYS_ENDPOINT_PATH = "/api/v1/old/pk";
    private static final String FETCH_PUBLIC_KEYS_ENDPOINT_PATH = "/api/v1/old/keys/";

    private final KeyStorage keyStorage;
    private final KeyFactory keyFactory;
    private final EncryptionService encryptionService;
    private final HttpClient httpClient;
    private final KeyEnvelopeService keyEnvelopeService;
    private final JwtConfig jwtConfig;

    public BlindnetClient(KeyStorage keyStorage,
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
     * Registers user on Blindnet API.
     *
     * @param publicEncryptionKey user's public key used for encryption.
     * @param publicSigningKey    user's public key used for signing.
     * @param signedJwt           signed Jwt object,
     * @return a user registration result object.
     */
    public UserRegistrationResult register(PublicKey publicEncryptionKey, PublicKey publicSigningKey, String signedJwt) {
        requireNonNull(publicEncryptionKey, "Public Encryption Key cannot be null.");
        requireNonNull(publicSigningKey, "Public Signing Key cannot be null.");
        requireNonNull(signedJwt, "Signed JWT cannot be null.");

        JSONObject requestBody = new JSONObject();
        requestBody.append("publicEncryptionKey", Base64.getUrlEncoder().encodeToString(publicEncryptionKey.getEncoded()));
        requestBody.append("publicSigningKey", Base64.getUrlEncoder().encodeToString(publicSigningKey.getEncoded()));
        requestBody.append("signedJwt", signedJwt);

        HttpResponse httpResponse = httpClient.post(BLINDNET_SERVER_URL + USER_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."),
                requestBody.toString().getBytes(StandardCharsets.UTF_8));

        return new UserRegistrationResult(httpResponse.getStatus() == HttpURLConnection.HTTP_OK, httpResponse.getMessage());
    }

    /**
     * Unregisters a user from Blindnet API.
     */
    public void unregister() {
        httpClient.delete(BLINDNET_SERVER_URL + USER_ENDPOINT_PATH,
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

        JSONObject requestBody = new JSONObject();
        requestBody.put("senderEnvelope", new JSONObject(senderKeyEnvelope));
        requestBody.put("recipientEnvelope", new JSONObject(recipientKeyEnvelope));

        httpClient.post(BLINDNET_SERVER_URL + SEND_SYMMETRIC_KEY_ENDPOINT_PATH,
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

        HttpResponse httpResponse = httpClient.get(BLINDNET_SERVER_URL + FETCH_SYMMETRIC_KEY_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));

        JSONObject responseBody = new JSONObject(new String(httpResponse.getBody()));
        KeyEnvelope keyEnvelope = new KeyEnvelope.Builder(responseBody.getString("envelopeID"))
                .withKey(responseBody.getString("key"))
                .withOwnerId(responseBody.getString("ownerID"))
                .withRecipientId(responseBody.getString("recipientID"))
                .withSenderId(responseBody.getString("senderID"))
                .withVersion(responseBody.getString("envelopeVersion"))
                .timestamp(responseBody.getLong("timestamp"))
                .build();

        // use local signing public key if the current user is not recipient otherwise pull it from blindnet api
        PublicKey signingKey = JwtUtil.extractUserId(jwtConfig.getJwt()).equals(recipientId) ?
                fetchPublicKeys(senderId).getSigningKey() :
                keyFactory.extractPublicKey(keyStorage.readSigningPrivateKey(),
                        ECDSA_ALGORITHM,
                        BC_PROVIDER,
                        SECRP_256_R_CURVE);

        String keyEnvelopeSignature = responseBody.getString("envelopeSignature");
        if (!keyEnvelopeService.verify(keyEnvelope, keyEnvelopeSignature, signingKey)) {
            String msg = "Unable to verify key envelope signature.";
            LOGGER.log(Level.SEVERE, msg);
            throw new SignatureException(msg);
        }

        return (SecretKey) encryptionService.unwrap(keyEnvelope.getKey().getBytes(),
                keyStorage.readEncryptionPrivateKey());
    }

    /**
     * Sends encrypted signing and encryption private keys of a user to the Blindnet API.
     *
     * @param encryptedPrivateEncryptionKey a encrypted private key object used for encryption.
     * @param encryptedPrivateSigningKey    a encrypted private key object used for signing.
     */
    public void sendPrivateKeys(String encryptedPrivateEncryptionKey, String encryptedPrivateSigningKey) {
        requireNonNull(encryptedPrivateEncryptionKey, "Encryption Private Key cannot be null.");
        requireNonNull(encryptedPrivateSigningKey, "Signing Private Key cannot be null.");

        JSONObject requestBody = new JSONObject();
        requestBody.put("encryptedPrivateEncryptionKey", new JSONObject(encryptedPrivateEncryptionKey));
        requestBody.put("encryptedPrivateSigningKey", new JSONObject(encryptedPrivateSigningKey));

        httpClient.post(BLINDNET_SERVER_URL + PRIVATE_KEYS_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."),
                requestBody.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Fetches encrypted signing and encryption private keys of a user from Blindnet API.
     *
     * @return a private key pair object.
     */
    public PrivateKeyPair fetchPrivateKeys() {
        HttpResponse httpResponse = httpClient.get(BLINDNET_SERVER_URL + PRIVATE_KEYS_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));

        JSONObject responseBody = new JSONObject(new String(httpResponse.getBody()));
        return new PrivateKeyPair(responseBody.getString("encryptedPrivateEncryptionKey"),
                responseBody.getString("encryptedPrivateSigningKey"));
    }

    /**
     * Fetches encryption and signing public keys of a user from Blindnet API.
     *
     * @param recipientId an id of a user whose keys are requested,
     * @return a public key pair object.
     */
    public PublicKeyPair fetchPublicKeys(String recipientId) {
        requireNonNull(recipientId, "Recipient ID cannot be null.");

        HttpResponse httpResponse = httpClient.get(BLINDNET_SERVER_URL + FETCH_PUBLIC_KEYS_ENDPOINT_PATH + recipientId,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));

        JSONObject responseBody = new JSONObject(new String(httpResponse.getBody()));
        PublicKey encryptionKey = keyFactory.convertToPublicKey(
                responseBody.getString("publicEncryptionKey"),
                RSA_ALGORITHM);
        PublicKey signingKey = keyFactory.convertToPublicKey(
                responseBody.getString("publicSigningKey"),
                ECDSA_ALGORITHM);

        return new PublicKeyPair(encryptionKey, signingKey);
    }

}
