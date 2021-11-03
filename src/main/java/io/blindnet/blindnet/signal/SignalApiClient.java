package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.*;
import io.blindnet.blindnet.internal.ApiConfig;
import io.blindnet.blindnet.internal.HttpClient;
import io.blindnet.blindnet.internal.JwtConfig;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.*;

import static io.blindnet.blindnet.internal.ApiClientConstants.*;
import static java.util.Objects.nonNull;
import static java.util.Objects.requireNonNull;

public class SignalApiClient {

    private final HttpClient httpClient;
    private final SignalKeyFactory signalKeyFactory;
    private final JwtConfig jwtConfig;
    private final ApiConfig apiConfig;

    public SignalApiClient(HttpClient httpClient,
                           SignalKeyFactory signalKeyFactory) {

        this.httpClient = httpClient;
        this.signalKeyFactory = signalKeyFactory;
        this.jwtConfig = JwtConfig.INSTANCE;
        this.apiConfig = ApiConfig.INSTANCE;
    }

    /**
     * Register Signal user against Blindnet api.
     *
     * @param deviceID device id.
     * @param userIdentityKey user's identity key.
     * @param publicIdentityKey public identity key.
     * @param identityKeyPairID identity key pair id.
     * @param publicPreKey public pre key.
     * @param preKeyPairID pre key pair id.
     * @param publicPreKeySignature signature of the public pre key.
     * @param listOfPublicPreKeys a list of public pre keys with their corresponding ids.
     * @param signedJwt signed jwt.
     *
     * @return a user registration result object.
     */
    public UserRegistrationResult register(String deviceID,
                                           String userIdentityKey,
                                           String publicIdentityKey,
                                           String identityKeyPairID,
                                           String publicPreKey,
                                           String preKeyPairID,
                                           String publicPreKeySignature,
                                           Map<String, String> listOfPublicPreKeys,
                                           String signedJwt) {

        requireNonNull(deviceID, "Device ID cannot be null.");
        requireNonNull(userIdentityKey, "User identity key cannot be null.");
        requireNonNull(publicIdentityKey, "Public identity key cannot be null.");
        requireNonNull(identityKeyPairID, "Identity key pair cannot be null.");
        requireNonNull(publicPreKey, "Public pre key cannot be null.");
        requireNonNull(preKeyPairID, "Pre key pair ID cannot be null.");
        requireNonNull(publicPreKeySignature, "Public pre key signature cannot be null.");
        requireNonNull(listOfPublicPreKeys, "List of public pre keys cannot be null.");
        requireNonNull(signedJwt, "Signed Jwt cannot be null.");

        JSONArray signalOneTimeKeysArr = new JSONArray();
        listOfPublicPreKeys.keySet().forEach(k ->
                signalOneTimeKeysArr.put(new JSONObject().put("publicOpkID", k).put("publicOpk", listOfPublicPreKeys.get(k))));

        JSONObject requestBody = new JSONObject().put("deviceID", deviceID)
                .put("userIk", userIdentityKey)
                .put("publicIkID", identityKeyPairID)
                .put("publicIk", publicIdentityKey)
                .put("publicSpkID", preKeyPairID)
                .put("publicSpk", publicPreKey)
                .put("pkSig", publicPreKeySignature)
                .put("signalOneTimeKeys", signalOneTimeKeysArr)
                .put("signedJwt", signedJwt);

        HttpResponse httpResponse = httpClient.post(apiConfig.getServerUrl() + SIGNAL_USER_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."),
                requestBody.toString().getBytes());

        return new UserRegistrationResult(httpResponse.getStatus() == HttpURLConnection.HTTP_OK, httpResponse.getMessage());
    }

    /**
     * Uploads public pre keys to Blindnet api.
     *
     * @param deviceID id of a device.
     * @param listOfPublicPreKeys a list of public pre keys with their corresponding ids.
     */
    public void uploadPreKeys(String deviceID,
                              Map<String, String> listOfPublicPreKeys) {

        requireNonNull(deviceID, "Device ID cannot be null.");
        requireNonNull(listOfPublicPreKeys, "List of public pre keys cannot be null.");

        JSONArray signalOneTimeKeysArr = new JSONArray();
        listOfPublicPreKeys.keySet().forEach(k ->
                signalOneTimeKeysArr.put(new JSONObject().put("publicOpkID", k).put("publicOpk", listOfPublicPreKeys.get(k))));
        JSONObject requestBody = new JSONObject().put("deviceID", deviceID)
                .put("signalOneTimeKeys", signalOneTimeKeysArr);

        httpClient.put(apiConfig.getServerUrl() + SIGNAL_UPLOAD_PUBLIC_KEYS_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."),
                requestBody.toString().getBytes());
    }

    /**
     * Unregisters a signal user from Blindnet api.
     */
    public void unregister() {
        httpClient.delete(apiConfig.getServerUrl() + SIGNAL_DELETE_USER_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));
    }

    /**
     * Fetches set of signal public keys of a user.
     *
     * @param recipientID id of a recipient.
     */
    public List<BlindnetSignalPublicKeys> fetchPublicKeys(String recipientID) {
        requireNonNull(recipientID, "Recipient ID cannot be null.");

        HttpResponse httpResponse = httpClient.get(apiConfig.getServerUrl() + SIGNAL_FETCH_PUBLIC_KEYS_ENDPOINT_PATH + recipientID,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));

        JSONArray responseBody = new JSONArray(new String(httpResponse.getBody()));

        List<BlindnetSignalPublicKeys> result = new ArrayList<>();
        Base64.Decoder decoder = Base64.getDecoder();

        // todo refactor
        for (int i = 0; i < responseBody.length(); ++i) {
            result.add(new BlindnetSignalPublicKeys(responseBody.getJSONObject(i).getString("userID"),
                    responseBody.getJSONObject(i).getString("deviceID"),
                    responseBody.getJSONObject(i).getString("publicIkID"),
                    signalKeyFactory.convertToECPublicKey(decoder.decode(responseBody.getJSONObject(i).getString("publicIK"))),
                    responseBody.getJSONObject(i).getString("publicSpkID"),
                    signalKeyFactory.convertToECPublicKey(decoder.decode(responseBody.getJSONObject(i).getString("publicSpk"))),
                    decoder.decode(responseBody.getJSONObject(i).getString("pkSig")),
                    responseBody.getJSONObject(i).getString("publicOpkID"),
                    signalKeyFactory.convertToECPublicKey(decoder.decode(responseBody.getJSONObject(i).getString("publicOpk")))));
        }
        return result;
    }

    /**
     * Sends Signal encrypted message to the Blindnet api.
     *
     * @param senderDeviceId id of sender's device.
     * @param recipientId id of a recipient.
     * @param recipientDeviceId id of recipient's device.
     * @param message encrypted message using Signal protocol.
     * @param timestamp timestamp.
     * @param protocolVersion protocol version.
     * @param diffieHellmanKey Diffie Hellman protocol key.
     * @param publicIdentityKey public identity key.
     * @param publicEphemeralKey public ephemeral key.
     *
     * @return a signal message sending result object.
     */
    public SignalSendMessageResult sendMessage(String senderDeviceId,
                                               String recipientId,
                                               String recipientDeviceId,
                                               String message,
                                               String timestamp,
                                               String protocolVersion,
                                               String diffieHellmanKey,
                                               String publicIdentityKey,
                                               String publicEphemeralKey) {

        requireNonNull(recipientId, "Recipient id cannot be null.");
        requireNonNull(recipientDeviceId, "Recipient device id cannot be null.");
        requireNonNull(message, "Message cannot be null.");
        requireNonNull(timestamp, "Timestamp cannot be null.");
        requireNonNull(protocolVersion, "Protocol version cannot be null.");

        // todo typos
        JSONObject requestBody = new JSONObject().put("recipirntID", recipientId)
                .put("senderDeviceId", senderDeviceId)
                .put("recipientDeviceID", recipientDeviceId)
                .put("message", message)
                .put("timestamp", timestamp)
                .put("protocolVersion", protocolVersion);

        if (nonNull(diffieHellmanKey) && !diffieHellmanKey.isEmpty()) {
            requestBody.put("dhKey", diffieHellmanKey);
        }

        if (nonNull(publicIdentityKey) && nonNull(publicEphemeralKey)) {
            JSONObject senderKeys = new JSONObject().put("publicIk", publicIdentityKey)
                    .put("publikEk", publicEphemeralKey);
            requestBody.put("senderKeys", new JSONArray().put(senderKeys));
        }

        HttpResponse httpResponse = httpClient.post(apiConfig.getServerUrl() + SIGNAL_SEND_MESSAGE_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."),
                requestBody.toString().getBytes());

        return new SignalSendMessageResult(httpResponse.getStatus() == HttpURLConnection.HTTP_OK, httpResponse.getMessage());
    }

    // todo java doc
    public List<SignalDeviceIds> fetchUserDeviceIds(String userId) {
        requireNonNull(userId, "User id cannot be null.");

        HttpResponse httpResponse = httpClient.get(apiConfig.getServerUrl() + SIGNAL_FETCH_USER_DEVICE_IDS + "?id=" + userId,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));

        JSONArray response = new JSONArray(new String(httpResponse.getBody()));
        List<SignalDeviceIds> result = new ArrayList<>();
        response.forEach(obj -> result.add(SignalDeviceIds.create((JSONObject) obj)));
        return result;
    }

    /**
     * Fetches all user messages and returns comma separated list of message ids.
     *
     * @param deviceId id of the device.
     */
    public String fetchMessageIds(String deviceId) {
        requireNonNull(deviceId, "Device id cannot be null.");

        HttpResponse httpResponse = httpClient.get(apiConfig.getServerUrl() + SIGNAL_FETCH_MESSAGE_IDS_ENDPOINT_PATH + "?deviceID=" + deviceId,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));

        String list = new String(httpResponse.getBody());
        return list.substring(1, list.length() - 1);
    }

    // todo java doc
    public List<BlindnetSignalMessage> fetchMessages(String deviceId, String messageIds) {
        requireNonNull(deviceId, "Device id cannot be null.");
        requireNonNull(messageIds, "Message ids cannot be null.");

        String urlQueryParams = "?deviceID=" + deviceId + "&messageIDs=" + messageIds;
        HttpResponse httpResponse = httpClient.get(apiConfig.getServerUrl() + SIGNAL_FETCH_MESSAGES_ENDPOINT_PATH + urlQueryParams,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));

        JSONArray response = new JSONArray(new String(httpResponse.getBody()));
        List<BlindnetSignalMessage> result = new ArrayList<>();
        response.forEach(obj -> result.add(BlindnetSignalMessage.create((JSONObject) obj)));
        return result;
    }

    /**
     * Uploads a backup to the Blindnet api.
     *
     * @param salt a salt used for encryption key generation.
     * @param encryptedMessages a list of encrypted messages.
     */
    public void uploadBackup(String salt, boolean newBackup, List<String> encryptedMessages) {
        requireNonNull(salt, "Salt cannot be null.");
        requireNonNull(encryptedMessages, "List of encrypted messages cannot be null.");

        JSONArray encryptedMessagesJson = new JSONArray();
        encryptedMessages.forEach(encryptedMessagesJson::put);

        JSONObject requestBody = new JSONObject()
                .put("encryptedMessages", encryptedMessagesJson);

        httpClient.post(apiConfig.getServerUrl() + SIGNAL_UPLOAD_BACKUP_ENDPOINT_PATH + "?newBackup=" + newBackup + "&salt=" + salt,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."),
                requestBody.toString().getBytes());
    }

    /**
     * Uploads a backup to the Blindnet api.
     * @param salt a salt used for encryption key generation.
     * @param encryptedMessages an input stream of encrypted messages.
     */
    public void uploadBackup(String salt, boolean newBackup, InputStream encryptedMessages) {
        requireNonNull(salt, "Salt cannot be null.");
        requireNonNull(encryptedMessages, "Encrypted messages input stream cannot be null.");

        httpClient.post(apiConfig.getServerUrl() + SIGNAL_UPLOAD_BACKUP_ENDPOINT_PATH + "?newBackup=" + newBackup + "&salt=" + salt,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."),
                encryptedMessages);
    }

    /**
     * Fetches backup from Blindnet api.
     *
     * @return a list of encrypted messages.
     */
    public List<String> fetchBackup() {
        HttpResponse httpResponse = httpClient.get(apiConfig.getServerUrl() + SIGNAL_FETCH_BACKUP_MESSAGES_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));

        JSONArray response = new JSONArray(new JSONObject(
                new String(httpResponse.getBody())).getJSONArray("encryptedMessages"));
        List<String> encryptedMessages = new ArrayList<>();
        response.forEach(msg -> encryptedMessages.add(msg.toString()));
        return encryptedMessages;
    }

    /**
     * Fetches backup from Blindnet api in a form of stream.
     *
     * @return a http connection object that contains reference to the backup stream.
     */
    public HttpURLConnection fetchBackupAsStream() {
        return httpClient.getAsStream(apiConfig.getServerUrl() + SIGNAL_FETCH_BACKUP_MESSAGES_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));
    }

    /**
     * Fetches a salt used for generation of the key for backup encryption.
     *
     * @return a salt.
     */
    public String fetchBackupSalt() {
        HttpResponse httpResponse = httpClient.get(apiConfig.getServerUrl() + SIGNAL_FETCH_BACKUP_SALT_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));

        String salt = new String(httpResponse.getBody());
        return salt.substring(1, salt.length() - 1);
    }

}
