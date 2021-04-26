package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.*;
import io.blindnet.blindnet.exception.KeyConstructionException;
import io.blindnet.blindnet.exception.KeyGenerationException;
import io.blindnet.blindnet.exception.SignatureException;
import org.json.JSONObject;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.IOException;
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
     * todo java doc
     *
     * @param jwt
     * @param publicEncryptionKey
     * @param publicSigningKey
     * @param signedJwt
     * @return
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

        try {
            HttpResponse httpResponse = httpClient.post(BLINDNET_SERVER_URL + USER_ENDPOINT_PATH,
                    jwt,
                    requestBody.toString().getBytes(StandardCharsets.UTF_8));

            return new UserRegistrationResult(httpResponse.getStatus() == HttpURLConnection.HTTP_OK, httpResponse.getMessage());
        } catch (IOException e) {
            String msg = "IO Error while sending request to the Blindnet API.";
            LOGGER.log(Level.SEVERE, msg);
            return new UserRegistrationResult(false, msg);
        }
    }

    // todo: FR-SDK05

    /**
     * todo javadoc
     * @param jwt
     * @param senderKeyEnvelope
     * @param recipientKeyEnvelope
     */
    public void sendSecretKey(String jwt, KeyEnvelope senderKeyEnvelope, KeyEnvelope recipientKeyEnvelope) {
        requireNonNull(jwt, "JWT cannot be null.");
        requireNonNull(senderKeyEnvelope, "Sender Key Envelope cannot be null");
        requireNonNull(recipientKeyEnvelope, "Recipient Key Envelope cannot be null");

        JSONObject requestBody = new JSONObject();
        requestBody.put("senderEnvelope", new JSONObject(senderKeyEnvelope));
        requestBody.put("recipientEnvelope", new JSONObject(recipientKeyEnvelope));
        try {
            httpClient.post(BLINDNET_SERVER_URL + SEND_SYMMETRIC_KEY_ENDPOINT_PATH,
                    jwt,
                    requestBody.toString().getBytes(StandardCharsets.UTF_8));

        } catch (IOException exception) {
            String msg = "IO Error while sending secret key to Blindnet API. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyConstructionException(msg, exception);
        }
    }

    // todo: FR-SDK06
    /**
     * javadoc
     * @param jwt
     * @param senderId
     * @param recipientId
     * @return
     */
    public SecretKey fetchSecretKey(String jwt, String senderId, String recipientId) {
        requireNonNull(jwt, "JWT cannot be null.");
        requireNonNull(senderId, "Sender ID cannot be null.");
        requireNonNull(recipientId, "Recipient ID cannot be null.");

        try {
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

        } catch (IOException exception) {
            String msg = "IO Error while reading a private key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyConstructionException(msg, exception);
        } catch (NoSuchPaddingException exception) {
            String msg = "Invalid Padding Error while unwrapping secret key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyConstructionException(msg, exception);
        } catch (NoSuchAlgorithmException exception) {
            String msg = "Invalid Algorithm Error while unwrapping secret key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyConstructionException(msg, exception);
        } catch (NoSuchProviderException exception) {
            String msg = "Invalid Provider Error while unwrapping secret key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyConstructionException(msg, exception);
        } catch (InvalidKeyException exception) {
            String msg = "Invalid Key Error while unwrapping secret key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyConstructionException(msg, exception);
        }
    }

    public void sendPrivateKeys(String jwt, String encryptedPrivateEncryptionKey, String encryptedPrivateSigningKey) {
        requireNonNull(jwt, "JWT cannot be null.");
        requireNonNull(encryptedPrivateEncryptionKey, "Encryption Private Key cannot be null.");
        requireNonNull(encryptedPrivateSigningKey, "Signing Private Key cannot be null.");

        JSONObject requestBody = new JSONObject();
        requestBody.put("encryptedPrivateEncryptionKey", new JSONObject(encryptedPrivateEncryptionKey));
        requestBody.put("encryptedPrivateSigningKey", new JSONObject(encryptedPrivateSigningKey));

        try {
            httpClient.post(BLINDNET_SERVER_URL + PRIVATE_KEYS_ENDPOINT_PATH,
                    jwt,
                    requestBody.toString().getBytes(StandardCharsets.UTF_8));

        } catch (IOException exception) {
            String msg = "IO Error while sending private keys to Blindnet API. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyConstructionException(msg, exception);
        }
    }

    public PrivateKeyPair fetchPrivateKeys(String jwt) {
        requireNonNull(jwt, "JWT cannot be null.");

        try {
            HttpResponse httpResponse = httpClient.get(BLINDNET_SERVER_URL + PRIVATE_KEYS_ENDPOINT_PATH, jwt);

            JSONObject responseBody = new JSONObject(new String(httpResponse.getBody()));
            return new PrivateKeyPair(responseBody.getString("encryptedPrivateEncryptionKey"),
                    responseBody.getString("encryptedPrivateSigningKey"));

        } catch (IOException exception) {
            String msg = String.format("IO Error while fetching private keys from Blindnet API. %s",
                    exception.getMessage());
            LOGGER.log(Level.SEVERE, msg, exception);
            throw new KeyConstructionException(msg, exception);
        }
    }

    /**
     * Fetches encryption and signing public key of a user from Blindnet API.
     *
     * @param jwt         Jwt object used to authorize against Blindnet API.
     * @param recipientId Id of a user whose keys are requested,
     * @return Optional Public Key Pair Object.
     */
    public PublicKeyPair fetchPublicKeys(String jwt, String recipientId) {
        requireNonNull(jwt, "JWT cannot be null.");
        requireNonNull(recipientId, "Recipient ID cannot be null.");

        try {
            HttpResponse httpResponse = httpClient.get(BLINDNET_SERVER_URL + FETCH_PUBLIC_KEYS_ENDPOINT_PATH + recipientId, jwt);

            JSONObject responseBody = new JSONObject(new String(httpResponse.getBody()));
            PublicKey encryptionKey = KeyFactory.convertToPublicKey(
                    responseBody.getString("publicEncryptionKey"),
                    RSA_ALGORITHM);
            PublicKey signingKey = KeyFactory.convertToPublicKey(
                    responseBody.getString("publicSigningKey"),
                    ECDSA_ALGORITHM);

            return new PublicKeyPair(encryptionKey, signingKey);

        } catch (IOException exception) {
            String msg = String.format("IO Error while sending request to fetch public keys from Blindnet API. %s",
                    exception.getMessage());
            LOGGER.log(Level.SEVERE, msg, exception);
            throw new KeyGenerationException(msg, exception);
        } catch (NoSuchAlgorithmException exception) {
            String msg = String.format("Invalid algorithm during conversion of public key fetched from Blindnet API. %s",
                    exception.getMessage());
            LOGGER.log(Level.SEVERE, msg, exception);
            throw new KeyGenerationException(msg, exception);
        } catch (InvalidKeySpecException exception) {
            String msg = String.format("Invalid key spec during conversion of public key fetched from Blindnet API. %s",
                    exception.getMessage());
            LOGGER.log(Level.SEVERE, msg, exception);
            throw new KeyGenerationException(msg, exception);
        }
    }

}
