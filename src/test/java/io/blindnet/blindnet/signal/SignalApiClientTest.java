package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.*;
import io.blindnet.blindnet.internal.HttpClient;
import io.blindnet.blindnet.internal.KeyFactory;
import io.blindnet.blindnet.internal.SigningService;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

import java.net.HttpURLConnection;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

import static io.blindnet.blindnet.internal.EncryptionConstants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

public class SignalApiClientTest extends SignalAbstractTest {

    private SignalApiClient signalApiClient;

    @Mock
    private HttpClient httpClient;

    private KeyFactory keyFactory;
    private SigningService signingService;
    private SignalKeyFactory signalKeyFactory;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        keyFactory = new KeyFactory();
        signingService = new SigningService();
        signalKeyFactory = new SignalKeyFactory();

        signalApiClient = new SignalApiClient(httpClient, signalKeyFactory);
    }

    @Test
    @DisplayName("Test registration of a Signal user.")
    public void testRegister() throws InvalidKeyException {
        String msg = "Registration successful.";
        when(httpClient.post(anyString(), any(byte[].class)))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(msg)
                        .withBody(new byte[1])
                        .build());

        IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
        int registrationId = KeyHelper.generateRegistrationId(false);

        SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, ThreadLocalRandom.current().nextInt());
        KeyPair signingKeyPair = keyFactory.generateEd25519KeyPair();
        byte[] signedJwt = signingService.sign(TEST_JWT,
                signingKeyPair.getPrivate(),
                Ed25519_ALGORITHM);

        int startId = ThreadLocalRandom.current().nextInt();
        List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(startId, 10);
        Map<String, String> listOfPublicPreKeys = new HashMap<>();
        preKeys.forEach(key ->
                listOfPublicPreKeys.put(String.valueOf(key.getId()), encoder.encodeToString(
                        signalKeyFactory.removeKeyTypeByte(key.getKeyPair().getPublicKey().serialize()))));

        UserRegistrationResult result = signalApiClient.register(DEVICE_ONE_ID,
                encoder.encodeToString(keyFactory.encodeEd25519PublicKey(signingKeyPair.getPublic())),
                encoder.encodeToString(signalKeyFactory.removeKeyTypeByte(identityKeyPair.getPublicKey().serialize())),
                String.valueOf(registrationId),
                encoder.encodeToString(signalKeyFactory.removeKeyTypeByte(signedPreKey.getKeyPair().getPublicKey().serialize())),
                String.valueOf(signedPreKey.getId()),
                encoder.encodeToString(signedPreKey.getSignature()),
                listOfPublicPreKeys,
                Base64.getUrlEncoder().encodeToString(signedJwt));

        assertNotNull(result);
        assertTrue(result.isSuccessful());
        assertEquals(result.getMessage(), msg);
    }

    @Test
    @DisplayName("Test upload of pre keys.")
    public void testUploadPreKeys() {
        int startId = ThreadLocalRandom.current().nextInt();
        List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(startId, 10);
        Map<String, String> listOfPublicPreKeys = new HashMap<>();
        preKeys.forEach(key ->
                listOfPublicPreKeys.put(String.valueOf(key.getId()), encoder.encodeToString(
                        signalKeyFactory.removeKeyTypeByte(key.getKeyPair().getPublicKey().serialize()))));

        assertDoesNotThrow(() -> signalApiClient.uploadPreKeys(DEVICE_ONE_ID, listOfPublicPreKeys));
    }

    @Test
    @DisplayName("Test Signal user unregister process.")
    public void testUnregister() {
        when(httpClient.delete(anyString()))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(new byte[1])
                        .build());

        assertDoesNotThrow(() -> signalApiClient.unregister());
    }

    @Test
    @DisplayName("Test fetching of user's public keys.")
    public void testFetchPublicKeys() throws InvalidKeyException {
        JSONObject userOne = new JSONObject();
        userOne.put("userID", USER_ONE_ID);
        userOne.put("deviceID", DEVICE_ONE_ID);

        String publicIkID = UUID.randomUUID().toString();
        userOne.put("publicIkID", publicIkID);
        IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
        userOne.put("publicIK", encoder.encodeToString(signalKeyFactory.removeKeyTypeByte(identityKeyPair.getPublicKey().serialize())));

        String publicSpkID = UUID.randomUUID().toString();
        userOne.put("publicSpkID", publicSpkID);
        KeyPair signingKeyPair = keyFactory.generateEd25519KeyPair();
        userOne.put("publicSpk", encoder.encodeToString(keyFactory.encodeEd25519PublicKey(signingKeyPair.getPublic())));
        SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, ThreadLocalRandom.current().nextInt());
        userOne.put("pkSig", encoder.encodeToString(signedPreKey.getSignature()));

        String publicOpkID = UUID.randomUUID().toString();
        userOne.put("publicOpkID", publicOpkID);
        int startId = ThreadLocalRandom.current().nextInt();
        List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(startId, 1);
        userOne.put("publicOpk", encoder.encodeToString(signalKeyFactory.removeKeyTypeByte(preKeys.get(0).getKeyPair().getPublicKey().serialize())));

        JSONArray responseBody = new JSONArray();
        responseBody.put(userOne);

        when(httpClient.get(anyString()))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(responseBody.toString().getBytes())
                        .build());

        List<BlindnetSignalPublicKeys> publicKeys = signalApiClient.fetchPublicKeys(USER_ONE_ID, DEVICE_ONE_ID);

        assertEquals(publicKeys.size(), 1);
        assertEquals(publicKeys.get(0).getDeviceID(), DEVICE_ONE_ID);
        assertEquals(publicKeys.get(0).getUserID(), USER_ONE_ID);
        assertEquals(publicKeys.get(0).getOneTimePreKeyID(), publicOpkID);
        assertEquals(new String(publicKeys.get(0).getPublicOneTimePrKey().serialize()), new String(preKeys.get(0).getKeyPair().getPublicKey().serialize()));
        assertEquals(new String(publicKeys.get(0).getPreKeySignature()), new String(signedPreKey.getSignature()));
        assertEquals(publicKeys.get(0).getIdentityID(), publicIkID);
        assertEquals(new String(publicKeys.get(0).getPublicIdentityKey().serialize()), new String(identityKeyPair.getPublicKey().serialize()));
    }

    @Test
    @DisplayName("Test sending of message.")
    public void testSendMessage() throws NoSuchAlgorithmException {
        String msg = "Message sent successfully.";
        when(httpClient.post(anyString(), any(byte[].class)))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(msg)
                        .withBody(new byte[1])
                        .build());

        byte[] message = new byte[20];
        SecureRandom.getInstanceStrong().nextBytes(message);

        IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
        IdentityKeyPair ephemeralKeyPair = KeyHelper.generateIdentityKeyPair();
        KeyPair diffieHellmanKeyPair = keyFactory.generateEd25519KeyPair();

        LocalDateTime dateTime = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        SignalSendMessageResult signalSendMessageResult = signalApiClient.sendMessage(DEVICE_ONE_ID,
                SIGNAL_ADDRESS_ONE_NAME,
                DEVICE_ONE_ID,
                encoder.encodeToString(message),
                dateTime.format(formatter),
                "3",
                encoder.encodeToString(signalKeyFactory.removeKeyTypeByte(diffieHellmanKeyPair.getPublic().getEncoded())),
                encoder.encodeToString(signalKeyFactory.removeKeyTypeByte(identityKeyPair.getPublicKey().serialize())),
                encoder.encodeToString(signalKeyFactory.removeKeyTypeByte(ephemeralKeyPair.getPublicKey().serialize())));

        assertTrue(signalSendMessageResult.isSuccessful());
        assertEquals(signalSendMessageResult.getMessage(), msg);
    }

    @Test
    @DisplayName("Test fetching of user device ids.")
    public void testFetchUserDeviceIds() {
        JSONArray responseBody = new JSONArray();
        responseBody.put(new JSONObject().put("userID", USER_ONE_ID).put("deviceID", DEVICE_ONE_ID));
        responseBody.put(new JSONObject().put("userID", USER_ONE_ID).put("deviceID", DEVICE_TWO_ID));

        when(httpClient.get(anyString()))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(responseBody.toString().getBytes())
                        .build());

        List<SignalDevice> userDevices = signalApiClient.fetchUserDeviceIds(USER_ONE_ID);

        assertEquals(userDevices.size(), 2);
        assertEquals(userDevices.get(0).getUserId(), USER_ONE_ID);
        assertEquals(userDevices.get(1).getUserId(), USER_ONE_ID);
        assertEquals(userDevices.get(0).getDeviceId(), DEVICE_ONE_ID);
        assertEquals(userDevices.get(1).getDeviceId(), DEVICE_TWO_ID);
    }

    @Test
    @DisplayName("Test fetching user's message ids.")
    public void testFetchMessageIds() {
        String responseBody = "[100,200,300]";
        when(httpClient.get(anyString()))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(responseBody.getBytes())
                        .build());

        String response = signalApiClient.fetchMessageIds(DEVICE_ONE_ID);

        assertNotNull(responseBody);
        assertTrue(response.contains("100"));
        assertTrue(response.contains("200"));
        assertTrue(response.contains("300"));
    }

    @Test
    @DisplayName("Test fetching user's messages.")
    public void testFetchMessages() {
        int messageId = 100;
        String messageIds = "100";
        JSONObject msg = new JSONObject();
        msg.put("id", messageId);
        msg.put("senderID", "sender_id_1");
        msg.put("senderDeviceID", "sender_device_id_1");
        msg.put("recipientID", "recipient_id_1");
        msg.put("recipientDeviceID", "recipient_device_id_1");
        msg.put("protocolVersion", "3");
        msg.put("messageContent", "random-message-content");
        msg.put("dhKey", UUID.randomUUID().toString());
        msg.put("timeSent", UUID.randomUUID().toString());
        msg.put("timeDelivered", UUID.randomUUID().toString());
        msg.put("timeRead", UUID.randomUUID().toString());
        JSONObject senderKeys = new JSONObject();
        senderKeys.put("id", 11);
        senderKeys.put("publicIk", UUID.randomUUID().toString());
        senderKeys.put("publicEk", UUID.randomUUID().toString());
        senderKeys.put("messageID", messageId);
        msg.put("blindnetSignalMessageSenderKeys", senderKeys);
        msg.put("senderApplicationID", UUID.randomUUID().toString());
        msg.put("recipientApplicationID", UUID.randomUUID().toString());

        JSONArray responseBody = new JSONArray();
        responseBody.put(msg);

        when(httpClient.get(anyString()))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(responseBody.toString().getBytes())
                        .build());

        List<BlindnetSignalMessage> messages = signalApiClient.fetchMessages(DEVICE_ONE_ID, messageIds);

        assertEquals(messages.size(), 1);
        assertEquals(messages.get(0).getId(), messageId);
        assertEquals(messages.get(0).getSenderID(), "sender_id_1");
        assertEquals(messages.get(0).getSenderDeviceID(), "sender_device_id_1");
        assertEquals(messages.get(0).getProtocolVersion(), "3");
        assertEquals(messages.get(0).getSignalMessageSenderKeys().getId(), 11);
        assertEquals(messages.get(0).getSignalMessageSenderKeys().getMessageID(), messageId);
    }

    @Test
    @DisplayName("Test backup of messages.")
    public void testUploadBackup() {
        when(httpClient.post(anyString(), any(byte[].class)))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(new byte[1])
                        .build());

        byte[] salt = keyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, SALT_LENGTH);
        List<String> encryptedMessages = new ArrayList<>();
        encryptedMessages.add(UUID.randomUUID().toString());
        encryptedMessages.add(UUID.randomUUID().toString());
        encryptedMessages.add(UUID.randomUUID().toString());

        assertDoesNotThrow(() -> signalApiClient.uploadBackup(Base64.getUrlEncoder().encodeToString(salt),
                true,
                encryptedMessages));
    }

    @Test
    @DisplayName("Test fetching of backup.")
    public void testFetchBackup() {
        JSONArray messages = new JSONArray();
        messages.put("message_1");
        messages.put("message_2");
        messages.put("message_3");
        JSONObject responseBody = new JSONObject();
        responseBody.put("encryptedMessages", messages);

        when(httpClient.get(anyString()))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(responseBody.toString().getBytes())
                        .build());

        List<String> fetchedMessages = signalApiClient.fetchBackup();

        assertEquals(fetchedMessages.size(), 3);
        assertEquals(fetchedMessages.get(0), "message_1");
        assertEquals(fetchedMessages.get(2), "message_3");
    }

    @Test
    @DisplayName("Test fetching of backup's salt.")
    public void testFetchBackupSalt() {
        String salt = UUID.randomUUID().toString();
        String responseBody = "[" + salt + "]";
        when(httpClient.get(anyString()))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(responseBody.toString().getBytes())
                        .build());

        String fetchedSalt = signalApiClient.fetchBackupSalt();

        assertNotNull(fetchedSalt);
        assertEquals(fetchedSalt, salt);
    }

}
