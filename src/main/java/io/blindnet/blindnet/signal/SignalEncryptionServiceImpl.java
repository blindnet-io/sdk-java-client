package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.BlindnetSignalMessage;
import io.blindnet.blindnet.domain.BlindnetSignalPublicKeys;
import io.blindnet.blindnet.domain.SignalSendMessageResult;
import io.blindnet.blindnet.exception.EncryptionException;
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
import java.util.List;

import static java.lang.String.valueOf;

public class SignalEncryptionServiceImpl implements SignalEncryptionService {

    private final SignalApiClient signalApiClient;
    private final SessionStore sessionStore;
    private final PreKeyStore preKeyStore;
    private final SignedPreKeyStore signedPreKeyStore;
    private final SignalIdentityKeyStore signalIdentityKeyStore;

    private static final String SIGNAL_MSG_PROTOCOL = "2";
    private static final String PRE_KEY_SIGNAL_MSG_PROTOCOL = "3";

    // todo javadoc
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
        byte[] preparedMessage = messageArrayWrapper.prepare();
        recipientIds.forEach(recipientId -> {
            List<Integer> deviceIds = sessionStore.getSubDeviceSessions(recipientId);
            if (deviceIds.isEmpty()) {
                encryptNotExistingSession(recipientId, preparedMessage);
            } else {
                deviceIds.forEach(deviceId -> encrypt(new SignalProtocolAddress(recipientId, deviceId), preparedMessage));
            }
        });
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

    private void encryptNotExistingSession(String recipientId, byte[] preparedMessage) {
        List<BlindnetSignalPublicKeys> signalPublicKeysResponse = signalApiClient.fetchPublicKeys(recipientId);
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
                encrypt(address, preparedMessage);
            } catch (UntrustedIdentityException | InvalidKeyException exception) {
                throw new EncryptionException("Error cannot create signal session.");
            }
        });
    }

    private SignalSendMessageResult encrypt(SignalProtocolAddress address, byte[] data) {
        CiphertextMessage message;
        try {
            SessionCipher sessionCipher = new SessionCipher(sessionStore,
                    preKeyStore,
                    signedPreKeyStore,
                    signalIdentityKeyStore,
                    address);
            message = sessionCipher.encrypt(data);
        } catch (UntrustedIdentityException exception) {
            throw new EncryptionException("Error: cannot encrypt signal message.");
        }

        String protocolVersion = "";
        String diffieHellmanKey = "";
        String publicIdentityKey = null;
        String publicEphemeralKey = null;

        if (message instanceof PreKeySignalMessage) {
            protocolVersion = valueOf(message.getType());
            diffieHellmanKey = Base64.getEncoder().encodeToString(((PreKeySignalMessage) message).getWhisperMessage().getSenderRatchetKey().serialize());
            publicIdentityKey = Base64.getEncoder().encodeToString(((PreKeySignalMessage) message).getBaseKey().serialize());
            publicEphemeralKey = Base64.getEncoder().encodeToString(((PreKeySignalMessage) message).getIdentityKey().serialize());
        } else if (message instanceof SignalMessage) {
            protocolVersion = valueOf(message.getType());
            diffieHellmanKey = Base64.getEncoder().encodeToString(((SignalMessage) message).getSenderRatchetKey().serialize());
        }

        LocalDateTime dateTime = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

        return signalApiClient.sendMessage(valueOf(signalIdentityKeyStore.getLocalDeviceId()),
                address.getName(),
                valueOf(address.getDeviceId()),
                Base64.getEncoder().encodeToString(message.serialize()),
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
        try {
            if (PRE_KEY_SIGNAL_MSG_PROTOCOL.equals(blindnetSignalMessage.getProtocolVersion())) {
                PreKeySignalMessage message = new PreKeySignalMessage(Base64.getDecoder().decode(blindnetSignalMessage.getMessageContent()));
                return MessageArrayWrapper.process(ByteBuffer.wrap(sessionCipher.decrypt(message)));
            } else if (SIGNAL_MSG_PROTOCOL.equals(blindnetSignalMessage.getProtocolVersion())) {
                SignalMessage message = new SignalMessage(Base64.getDecoder().decode(blindnetSignalMessage.getMessageContent()));
                return MessageArrayWrapper.process(ByteBuffer.wrap(sessionCipher.decrypt(message)));
            } else {
                throw new EncryptionException("Unrecognized signal message protocol.");
            }
        } catch (Exception exception) {
            throw new EncryptionException("Error: cannot decrypt signal message.");
        }
    }

}
