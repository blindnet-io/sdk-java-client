package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.*;
import io.blindnet.blindnet.exception.EncryptionException;
import io.blindnet.blindnet.internal.JwtConfig;
import io.blindnet.blindnet.internal.JwtUtil;
import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.state.SessionStore;
import org.whispersystems.libsignal.state.SignedPreKeyStore;

import java.nio.ByteBuffer;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.lang.String.valueOf;

/**
 * Implementation of API used for encryption and decryption of messages using Signal Blindnet API.
 */
class SignalEncryptionServiceImpl implements SignalEncryptionService {

    private final SignalApiClient signalApiClient;
    private final SessionStore sessionStore;
    private final PreKeyStore preKeyStore;
    private final SignedPreKeyStore signedPreKeyStore;
    private final SignalIdentityKeyStore signalIdentityKeyStore;

    private static final String SIGNAL_MSG_PROTOCOL = "2";
    private static final String PRE_KEY_SIGNAL_MSG_PROTOCOL = "3";

    public SignalEncryptionServiceImpl(SignalApiClient signalApiClient,
                                       SessionStore sessionStore,
                                       PreKeyStore preKeyStore,
                                       SignedPreKeyStore signedPreKeyStore,
                                       SignalIdentityKeyStore signalIdentityKeyStore) {

        this.signalApiClient = signalApiClient;
        this.sessionStore = sessionStore;
        this.preKeyStore = preKeyStore;
        this.signedPreKeyStore = signedPreKeyStore;
        this.signalIdentityKeyStore = signalIdentityKeyStore;
    }

    @Override
    public void encryptMessage(List<String> recipientIds, MessageArrayWrapper messageArrayWrapper) {
        int localDeviceId = signalIdentityKeyStore.getLocalDeviceId();
        String currentUserId = JwtUtil.extractUserId(JwtConfig.INSTANCE.getJwt());

        recipientIds.forEach(recipientId ->
                calculateEncryption(recipientId, localDeviceId, currentUserId, messageArrayWrapper));
    }

    @Override
    public List<MessageArrayWrapper> decryptMessage(String deviceId) {
        String messageIds = signalApiClient.fetchMessageIds(deviceId);
        if (messageIds.isBlank()) {
            return List.of();
        }
        List<BlindnetSignalMessage> messages = signalApiClient.fetchMessages(deviceId, messageIds);
        List<MessageArrayWrapper> result = new ArrayList<>();
        messages.forEach(message -> result.add(decrypt(message)));
        return result;
    }

    /* Signal library does not support encryption of stream messages
     *
     * @Override
     * public void encryptMessage(List<String> recipientIds, MessageStreamWrapper messageStreamWrapper) {
     *   int localDeviceId = signalIdentityKeyStore.getLocalDeviceId();
     *   String currentUserId = JwtUtil.extractUserId(JwtConfig.INSTANCE.getJwt());
     *
     *   recipientIds.forEach(recipientId ->
     *           calculateEncryption(recipientId, localDeviceId, currentUserId, messageStreamWrapper));
     * }

    /* Signal library does not support encryption of stream messages
     *
     * @Override
     * public List<MessageStreamWrapper> decryptStreamMessage(String deviceId) {
     * }
     */

    private void calculateEncryption(String recipientId,
                                     int localDeviceId,
                                     String currentUserId,
                                     MessageWrapper messageWrapper) {
        List<Integer> deviceIds = sessionStore.getSubDeviceSessions(recipientId);

        // if there are no sessions with recipient devices, we send message to all devices of that recipient
        // and to all other devices of this user
        if (deviceIds.isEmpty()) {
            // public keys of all recipient devices
            List<BlindnetSignalPublicKeys> recipientPublicKeys = signalApiClient.fetchPublicKeys(recipientId, null);

            // list of other devices of this user
            List<String> currentUserDevices = signalApiClient.fetchUserDeviceIds(currentUserId)
                    .stream()
                    .map(SignalDevice::getDeviceId)
                    .filter(deviceId -> !deviceId.equals(String.valueOf(localDeviceId)))
                    .collect(Collectors.toList());

            // public keys of other devices of this user
            List<BlindnetSignalPublicKeys> currentUserOtherDevicesPublicKeys = currentUserDevices.isEmpty() ?
                    List.of() :
                    signalApiClient.fetchPublicKeys(recipientId, String.join(",", currentUserDevices));

            encryptNotExistingSession(recipientId,
                    Stream.of(recipientPublicKeys, currentUserOtherDevicesPublicKeys)
                            .flatMap(Collection::stream)
                            .collect(Collectors.toList()),
                    messageWrapper);
        }
        // if there are sessions with recipient devices and some of other devices of this user,
        // we send a session message to all these devices
        // and create new sessions for all devices we do not have session with at the moment
        else {
            // list of all devices of recipient
            List<SignalDevice> recipientDevices = signalApiClient.fetchUserDeviceIds(recipientId);

            // list of all devices of recipient that current user does not have session with
            List<String> recipientNoSessionDeviceIds = recipientDevices
                    .stream()
                    .map(SignalDevice::getDeviceId)
                    .filter(deviceId -> !deviceIds.contains(Integer.valueOf(deviceId)))
                    .collect(Collectors.toList());

            // list of public keys of all devices of recipient
            // that current user does not have session with
            List<BlindnetSignalPublicKeys> recipientPublicKeys = recipientNoSessionDeviceIds.isEmpty() ?
                    List.of() :
                    signalApiClient.fetchPublicKeys(recipientId, String.join(",", recipientNoSessionDeviceIds));

            // list of all devices of the current user excluding current device
            List<SignalDevice> currentUserDevices = signalApiClient.fetchUserDeviceIds(currentUserId)
                    .stream()
                    .filter(deviceId -> !deviceId.getDeviceId().equals(String.valueOf(localDeviceId)))
                    .collect(Collectors.toList());

            // list of all devices of the current user
            // that current device does not have session with
            List<String> currentUserNoSessionDeviceIds = currentUserDevices
                    .stream()
                    .map(SignalDevice::getDeviceId)
                    .filter(deviceId -> !deviceIds.contains(Integer.valueOf(deviceId)))
                    .collect(Collectors.toList());

            // list of public keys of all devices of current user
            // that current device does not have session with
            List<BlindnetSignalPublicKeys> currentUserOtherDevicesPublicKeys = currentUserNoSessionDeviceIds.isEmpty() ?
                    List.of() :
                    signalApiClient.fetchPublicKeys(recipientId, String.join(",", currentUserNoSessionDeviceIds));

            // send message and create session with devices there is no session with at the moment
            encryptNotExistingSession(recipientId,
                    Stream.of(recipientPublicKeys, currentUserOtherDevicesPublicKeys)
                            .flatMap(Collection::stream)
                            .collect(Collectors.toList()),
                    messageWrapper);

            // send message to all devices there is a session with already
            deviceIds.forEach(deviceId -> encrypt(new SignalProtocolAddress(recipientId, deviceId), messageWrapper));
        }
    }

    private void encryptNotExistingSession(String recipientId,
                                           List<BlindnetSignalPublicKeys> signalPublicKeysResponse,
                                           MessageWrapper messageWrapper) {

        signalPublicKeysResponse.forEach(spk -> {
            SignalProtocolAddress address = new SignalProtocolAddress(recipientId, Integer.parseInt(spk.getDeviceID()));
            SessionBuilder sessionBuilder = new SessionBuilder(sessionStore,
                    preKeyStore,
                    signedPreKeyStore,
                    signalIdentityKeyStore,
                    address);

            PreKeyBundle preKeyBundle = new PreKeyBundle(Integer.parseInt(spk.getIdentityID()),
                    Integer.parseInt(spk.getDeviceID()),
                    Integer.parseInt(spk.getOneTimePreKeyID()),
                    spk.getPublicOneTimePrKey(),
                    Integer.parseInt(spk.getPreKeyPairID()),
                    spk.getPublicPreKey(),
                    spk.getPreKeySignature(),
                    new IdentityKey(spk.getPublicIdentityKey()));

            try {
                sessionBuilder.process(preKeyBundle);
                encrypt(address, messageWrapper);
            } catch (UntrustedIdentityException | InvalidKeyException exception) {
                throw new EncryptionException("Error cannot create signal session.");
            }
        });
    }

    private SignalSendMessageResult encrypt(SignalProtocolAddress address, MessageWrapper messageWrapper) {
        CiphertextMessage message;
        byte[] preparedMessage;
        if (messageWrapper instanceof MessageArrayWrapper) {
            preparedMessage = ((MessageArrayWrapper) messageWrapper).prepare();
        } else {
            // stream wrapper use case
            // currently Signal library does not support encryption of messages in form of stream
            preparedMessage = new byte[2048];
        }
        try {
            SessionCipher sessionCipher = new SessionCipher(sessionStore,
                    preKeyStore,
                    signedPreKeyStore,
                    signalIdentityKeyStore,
                    address);
            message = sessionCipher.encrypt(preparedMessage);
        } catch (UntrustedIdentityException exception) {
            throw new EncryptionException("Error: cannot encrypt signal message.");
        }

        Base64.Encoder encoder = Base64.getEncoder();
        String protocolVersion;
        String diffieHellmanKey;
        String publicIdentityKey = null;
        String publicEphemeralKey = null;

        if (message instanceof PreKeySignalMessage) {
            protocolVersion = valueOf(message.getType());
            diffieHellmanKey = encoder.encodeToString(((PreKeySignalMessage) message).getWhisperMessage().getSenderRatchetKey().serialize());
            publicIdentityKey = encoder.encodeToString(((PreKeySignalMessage) message).getBaseKey().serialize());
            publicEphemeralKey = encoder.encodeToString(((PreKeySignalMessage) message).getIdentityKey().serialize());
        } else if (message instanceof SignalMessage) {
            protocolVersion = valueOf(message.getType());
            diffieHellmanKey = encoder.encodeToString(((SignalMessage) message).getSenderRatchetKey().serialize());
        } else {
            throw new EncryptionException("Error: cannot encrypt signal message.");
        }

        LocalDateTime dateTime = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

        return signalApiClient.sendMessage(valueOf(signalIdentityKeyStore.getLocalDeviceId()),
                address.getName(),
                valueOf(address.getDeviceId()),
                encoder.encodeToString(message.serialize()),
                dateTime.format(formatter),
                protocolVersion,
                diffieHellmanKey,
                publicIdentityKey,
                publicEphemeralKey);
    }

    private MessageArrayWrapper decrypt(BlindnetSignalMessage blindnetSignalMessage) {
        SignalProtocolAddress address = new SignalProtocolAddress(blindnetSignalMessage.getSenderID(),
                Integer.parseInt(blindnetSignalMessage.getSenderDeviceID()));
        SessionCipher sessionCipher = new SessionCipher(sessionStore,
                preKeyStore,
                signedPreKeyStore,
                signalIdentityKeyStore,
                address);
        String protocolVersion = blindnetSignalMessage.getProtocolVersion();
        byte[] messageContent = Base64.getDecoder().decode(blindnetSignalMessage.getMessageContent());
        try {
            if (PRE_KEY_SIGNAL_MSG_PROTOCOL.equals(protocolVersion)) {
                PreKeySignalMessage message = new PreKeySignalMessage(messageContent);
                return MessageArrayWrapper.process(ByteBuffer.wrap(sessionCipher.decrypt(message)));
            } else if (SIGNAL_MSG_PROTOCOL.equals(protocolVersion)) {
                SignalMessage message = new SignalMessage(messageContent);
                return MessageArrayWrapper.process(ByteBuffer.wrap(sessionCipher.decrypt(message)));
            } else {
                throw new EncryptionException("Unrecognized signal message protocol.");
            }
        } catch (Exception exception) {
            throw new EncryptionException("Error: cannot decrypt signal message.");
        }
    }

}
