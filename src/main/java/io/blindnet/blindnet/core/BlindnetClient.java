package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.*;
import io.blindnet.blindnet.exception.KeyConstructionException;
import io.blindnet.blindnet.exception.KeyGenerationException;
import io.blindnet.blindnet.exception.SignatureException;
import org.json.JSONObject;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
import static java.util.Objects.requireNonNull;

// todo Check if this should be singleton
// todo make class package view

/**
 * Provides API for communication with Blindnet API.
 *
 * @author stefanveselinovic
 */
public class BlindnetClient {

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

    private final HttpClient httpClient;
    private final JwtService jwtService;
    private final KeyStorage keyStorage;
    private final KeyEnvelopeService keyEnvelopeService;
    private final EncryptionService encryptionService;

    public BlindnetClient() {
        // todo check
        httpClient = new HttpClient();
        jwtService = new JwtService();
        keyStorage = new KeyStorage();
        keyEnvelopeService = new KeyEnvelopeService();
        encryptionService = new EncryptionService();
    }

    /**
     * Registers user on Blindnet API.
     *
     * @param jwt                 a Jwt object used to authenticate against Blindnet API.
     * @param publicEncryptionKey user's Public Key used for encryption.
     * @param publicSigningKey    user's Public Key used for signing.
     * @param signedJwt           signed Jwt object,
     * @return User Registration Result object,
     */
    public UserRegistrationResult register(String jwt, PublicKey publicEncryptionKey, PublicKey publicSigningKey, String signedJwt) {
        requireNonNull(jwt, "JWT cannot be null.");
        requireNonNull(publicEncryptionKey, "Public Encryption Key cannot be null.");
        requireNonNull(publicSigningKey, "Public Signing Key cannot be null.");
        requireNonNull(signedJwt, "Signed JWT cannot be null.");

        JSONObject requestBody = new JSONObject();
        requestBody.append("publicEncryptionKey", Base64.getUrlEncoder().encodeToString(publicEncryptionKey.getEncoded()));
        requestBody.append("publicSigningKey", Base64.getUrlEncoder().encodeToString(publicSigningKey.getEncoded()));
        requestBody.append("signedJwt", signedJwt);

        HttpResponse httpResponse = httpClient.post(BLINDNET_SERVER_URL + USER_ENDPOINT_PATH,
                jwt,
                requestBody.toString().getBytes(StandardCharsets.UTF_8));

        return new UserRegistrationResult(httpResponse.getStatus() == HttpURLConnection.HTTP_OK, httpResponse.getMessage());
    }

    /**
     * Unregisters a user from Blindnet API.
     *
     * @param jwt a Jwt object used to authenticate against Blindnet API.
     */
    public void unregister(String jwt) {
        requireNonNull(jwt, "JWT cannot be null.");

        httpClient.delete(BLINDNET_SERVER_URL + USER_ENDPOINT_PATH, jwt);
    }

    /**
     * Sends a Secret Key of a user doubly encrypted and wrapped into an Envelop object,
     *
     * @param jwt                  a Jwt object used to authenticate against Blindnet API.
     * @param senderKeyEnvelope    an Envelop object which contains a user's Secret Key encrypted using sender's key.
     * @param recipientKeyEnvelope an Envelop object which contains a user's Secret Key encrypted using recipient's key.
     */
    public void sendSecretKey(String jwt, KeyEnvelope senderKeyEnvelope, KeyEnvelope recipientKeyEnvelope) {
        requireNonNull(jwt, "JWT cannot be null.");
        requireNonNull(senderKeyEnvelope, "Sender Key Envelope cannot be null");
        requireNonNull(recipientKeyEnvelope, "Recipient Key Envelope cannot be null");

        JSONObject requestBody = new JSONObject();
        requestBody.put("senderEnvelope", new JSONObject(senderKeyEnvelope));
        requestBody.put("recipientEnvelope", new JSONObject(recipientKeyEnvelope));

        httpClient.post(BLINDNET_SERVER_URL + SEND_SYMMETRIC_KEY_ENDPOINT_PATH,
                jwt,
                requestBody.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Fetches a Secret Key of a user from Blindnet API and validates a signature of an Envelope.
     *
     * @param jwt         a Jwt object used to authenticate against Blindnet API.
     * @param senderId    a sender ID.
     * @param recipientId a recipient ID.
     * @return a Secret Key Object.
     */
    public SecretKey fetchSecretKey(String jwt, String senderId, String recipientId) {
        requireNonNull(jwt, "JWT cannot be null.");
        requireNonNull(senderId, "Sender ID cannot be null.");
        requireNonNull(recipientId, "Recipient ID cannot be null.");

        HttpResponse httpResponse = httpClient.get(BLINDNET_SERVER_URL + FETCH_SYMMETRIC_KEY_ENDPOINT_PATH, jwt);

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
        PublicKey signingKey = jwtService.extractUserId(jwt).equals(recipientId) ?
                fetchPublicKeys(jwt, senderId).getSigningKey() :
                KeyFactory.extractPublicKey(keyStorage.readSigningPrivateKey(),
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
     * @param jwt                           a Jwt object used to authenticate against Blindnet API.
     * @param encryptedPrivateEncryptionKey a Encrypted Private Key object used for encryption.
     * @param encryptedPrivateSigningKey    a Encrypted Private Key object used for signing.
     */
    public void sendPrivateKeys(String jwt, String encryptedPrivateEncryptionKey, String encryptedPrivateSigningKey) {
        requireNonNull(jwt, "JWT cannot be null.");
        requireNonNull(encryptedPrivateEncryptionKey, "Encryption Private Key cannot be null.");
        requireNonNull(encryptedPrivateSigningKey, "Signing Private Key cannot be null.");

        JSONObject requestBody = new JSONObject();
        requestBody.put("encryptedPrivateEncryptionKey", new JSONObject(encryptedPrivateEncryptionKey));
        requestBody.put("encryptedPrivateSigningKey", new JSONObject(encryptedPrivateSigningKey));

        httpClient.post(BLINDNET_SERVER_URL + PRIVATE_KEYS_ENDPOINT_PATH,
                jwt,
                requestBody.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Fetches encrypted signing and encryption private keys of a user from Blindnet API.
     *
     * @param jwt a Jwt object used to authenticate against Blindnet API.
     * @return a Private Key Pair object.
     */
    public PrivateKeyPair fetchPrivateKeys(String jwt) {
        requireNonNull(jwt, "JWT cannot be null.");

        HttpResponse httpResponse = httpClient.get(BLINDNET_SERVER_URL + PRIVATE_KEYS_ENDPOINT_PATH, jwt);

        JSONObject responseBody = new JSONObject(new String(httpResponse.getBody()));
        return new PrivateKeyPair(responseBody.getString("encryptedPrivateEncryptionKey"),
                responseBody.getString("encryptedPrivateSigningKey"));
    }

    /**
     * Fetches encryption and signing public keys of a user from Blindnet API.
     *
     * @param jwt         a Jwt object used to authenticate against Blindnet API.
     * @param recipientId Id of a user whose keys are requested,
     * @return a Public Key Pair Object.
     */
    public PublicKeyPair fetchPublicKeys(String jwt, String recipientId) {
        requireNonNull(jwt, "JWT cannot be null.");
        requireNonNull(recipientId, "Recipient ID cannot be null.");

        HttpResponse httpResponse = httpClient.get(BLINDNET_SERVER_URL + FETCH_PUBLIC_KEYS_ENDPOINT_PATH + recipientId, jwt);

        JSONObject responseBody = new JSONObject(new String(httpResponse.getBody()));
        PublicKey encryptionKey = KeyFactory.convertToPublicKey(
                responseBody.getString("publicEncryptionKey"),
                RSA_ALGORITHM);
        PublicKey signingKey = KeyFactory.convertToPublicKey(
                responseBody.getString("publicSigningKey"),
                ECDSA_ALGORITHM);

        return new PublicKeyPair(encryptionKey, signingKey);
    }

}
