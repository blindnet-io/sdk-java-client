package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.HttpResponse;
import io.blindnet.blindnet.domain.SignalPublicKeys;
import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.internal.ApiConfig;
import io.blindnet.blindnet.internal.HttpClient;
import io.blindnet.blindnet.internal.JwtConfig;
import io.blindnet.blindnet.internal.KeyFactory;
import org.json.JSONArray;
import org.json.JSONObject;

import java.net.HttpURLConnection;
import java.security.PublicKey;
import java.util.Map;

import static io.blindnet.blindnet.internal.ApiClientConstants.*;
import static io.blindnet.blindnet.internal.EncryptionConstants.Ed25519_ALGORITHM;
import static java.util.Objects.requireNonNull;

public class SignalApiClient {

    private final HttpClient httpClient;
    private final KeyFactory keyFactory;
    private final JwtConfig jwtConfig;
    private final ApiConfig apiConfig;

    SignalApiClient(HttpClient httpClient,
                    KeyFactory keyFactory) {

        this.httpClient = httpClient;
        this.keyFactory = keyFactory;
        this.jwtConfig = JwtConfig.INSTANCE;
        this.apiConfig = ApiConfig.INSTANCE;
    }

    public UserRegistrationResult register(String jwt,
                                           String deviceID,
                                           String publicIdentityKey,
                                           String identityKeyPairID,
                                           String publicPreKey,
                                           String preKeyPairID,
                                           String publicPreKeySignature,
                                           Map<String, String> listOfPublicPreKeys,
                                           String signedJwt) {

        requireNonNull(jwt, "Jwt cannot be null.");
        requireNonNull(deviceID, "Device ID cannot be null.");
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
                .put("publicIkID", identityKeyPairID)
                .put("publicIk", publicIdentityKey)
                .put("publicSpkID", preKeyPairID)
                .put("publicSpk", publicPreKey)
                .put("pkSig", publicPreKeySignature)
                .put("signalOneTimeKeys", signalOneTimeKeysArr)
                .put("signedJwt", signedJwt);

        HttpResponse httpResponse = httpClient.post(apiConfig.getServerUrl() + SIGNAL_USER_ENDPOINT_PATH,
                jwt,
                requestBody.toString().getBytes());

        return new UserRegistrationResult(httpResponse.getStatus() == HttpURLConnection.HTTP_OK, httpResponse.getMessage());
    }

    /**
     *
     */
    public void unregister() {
        httpClient.delete(apiConfig.getServerUrl() + SIGNAL_DELETE_USER_ENDPOINT_PATH,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));
    }

    /**
     * @param recipientID
     */
    public SignalPublicKeys fetchPublicKeys(String recipientID) {
        requireNonNull(recipientID, "Recipient ID cannot be null.");

        HttpResponse httpResponse = httpClient.get(apiConfig.getServerUrl() + SIGNAL_FETCH_PUBLIC_KEYS_ENDPOINT_PATH + recipientID,
                requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));

        JSONObject responseBody = new JSONObject(new String(httpResponse.getBody()));
        String deviceID = responseBody.getString("deviceID");
        PublicKey publicIK = keyFactory.convertToPublicKey(responseBody.getString("publicIK"),
                Ed25519_ALGORITHM);
        PublicKey publicSpk = keyFactory.convertToPublicKey(responseBody.getString("publicSpk"),
                Ed25519_ALGORITHM);
        String publicSpkID = responseBody.getString("publicSpkID");

        // todo check if onetimeprekeys should  be  in array
        ///PublicKey publicOneTimePreKey = keyFactory.convertToPublicKey(responseBody.get("signalOneTimeKeys"))

        return new SignalPublicKeys(deviceID,
                publicIK,
                publicSpk,
                publicSpkID,
                null,
                null);
    }

}
