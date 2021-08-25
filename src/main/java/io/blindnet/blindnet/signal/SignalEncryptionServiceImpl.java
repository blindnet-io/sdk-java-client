package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.BlindnetSignalMessage;
import io.blindnet.blindnet.domain.BlindnetSignalPublicKeys;
import io.blindnet.blindnet.domain.SignalSendMessageResult;
import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.state.SessionStore;
import org.whispersystems.libsignal.state.SignedPreKeyStore;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class SignalEncryptionServiceImpl implements SignalEncryptionService {

    private final SignalApiClient signalApiClient;
    private final SessionStore sessionStore;
    private final PreKeyStore preKeyStore;
    private final SignedPreKeyStore signedPreKeyStore;
    private final SignalIdentityKeyStore signalIdentityKeyStore;

    // todo exception handling
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
        recipientIds.forEach(recipientId -> {
            List<BlindnetSignalPublicKeys> signalPublicKeysResponse = signalApiClient.fetchPublicKeys(recipientId);
            signalPublicKeysResponse.forEach( signalPublicKeys -> encrypt(recipientId, signalPublicKeys, messageArrayWrapper.prepare()));
        });
    }

    @Override
    public List<MessageArrayWrapper> decryptMessage(String recipientId, String deviceId) {
        List<BlindnetSignalMessage> messages = signalApiClient.fetchMessages(deviceId, signalApiClient.fetchMessageIds(deviceId));
        List<MessageArrayWrapper> result = new ArrayList<>();
        messages.forEach(message -> result.add(decrypt(message)));
        return result;
    }

    private SignalSendMessageResult encrypt(String recipientId, BlindnetSignalPublicKeys signalPublicKeysResponse, byte[] data) {
        // todo check logic
        // todo refactor
        SignalProtocolAddress address = new SignalProtocolAddress(recipientId, Integer.parseInt(signalPublicKeysResponse.getDeviceID()));
        SessionBuilder sessionBuilder = new SessionBuilder(sessionStore,
                preKeyStore,
                signedPreKeyStore,
                signalIdentityKeyStore,
                address);


        PreKeyBundle preKeyBundle = new PreKeyBundle(Integer.parseInt(signalPublicKeysResponse.getIdentityID()),
                Integer.parseInt(signalPublicKeysResponse.getDeviceID()),
                Integer.parseInt(signalPublicKeysResponse.getOneTimePreKeyID()),
                signalPublicKeysResponse.getPublicOneTimePrKey(),
                Integer.parseInt(signalPublicKeysResponse.getPreKeyPairID()),
                signalPublicKeysResponse.getPublicPreKey(),
                signalPublicKeysResponse.getPreKeySignature(),
                new IdentityKey(signalPublicKeysResponse.getPublicIdentityKey()));

        try {
            sessionBuilder.process(preKeyBundle);

            SessionCipher sessionCipher = new SessionCipher(sessionStore,
                    preKeyStore,
                    signedPreKeyStore,
                    signalIdentityKeyStore,
                    address);
            CiphertextMessage message = sessionCipher.encrypt(data);

            // todo refactor
            String protocolVersion = "";
            String diffieHellmanKey = "";
            String publicIdentityKey = "";
            String publicEphemeralKey = "";

            if (message instanceof PreKeySignalMessage) {
                protocolVersion = String.valueOf(((PreKeySignalMessage) message).getMessageVersion());
                diffieHellmanKey = Base64.getEncoder().encodeToString(((PreKeySignalMessage) message).getWhisperMessage().getSenderRatchetKey().serialize());
                publicIdentityKey = Base64.getEncoder().encodeToString(((PreKeySignalMessage) message).getBaseKey().serialize());
                publicEphemeralKey = Base64.getEncoder().encodeToString(((PreKeySignalMessage) message).getIdentityKey().serialize());
            } else if (message instanceof SignalMessage) {
                protocolVersion = String.valueOf(((SignalMessage) message).getMessageVersion());
                diffieHellmanKey = Base64.getEncoder().encodeToString(((SignalMessage) message).getSenderRatchetKey().serialize());
            }

            LocalDateTime dateTime = LocalDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");

            return signalApiClient.sendMessage(recipientId,
                    signalPublicKeysResponse.getDeviceID(),
                    Base64.getEncoder().encodeToString(message.serialize()),
                    dateTime.format(formatter),
                    protocolVersion,
                    diffieHellmanKey,
                    publicIdentityKey.isEmpty() ? null : publicIdentityKey,
                    publicEphemeralKey.isEmpty() ? null : publicEphemeralKey);
        } catch (InvalidKeyException | UntrustedIdentityException e) {
            e.printStackTrace();
            return null;
        }
    }

    private MessageArrayWrapper decrypt(BlindnetSignalMessage blindnetSignalMessage) {
        SignalProtocolAddress address = new SignalProtocolAddress(blindnetSignalMessage.getRecipientID(),
                Integer.parseInt(blindnetSignalMessage.getRecipientDeviceID()));
        SessionCipher sessionCipher = new SessionCipher(sessionStore,
                preKeyStore,
                signedPreKeyStore,
                signalIdentityKeyStore,
                address);
        try {
            // todo check when is prekey signal message and when is just signal message
            PreKeySignalMessage msg = new PreKeySignalMessage(blindnetSignalMessage.getMessageContent().getBytes(StandardCharsets.UTF_8));
            return MessageArrayWrapper.process(ByteBuffer.wrap(sessionCipher.decrypt(msg)));
        } catch (Exception exception) {
            return null;
        }
    }

}
