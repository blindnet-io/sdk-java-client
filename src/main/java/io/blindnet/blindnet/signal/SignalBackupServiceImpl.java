package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.internal.EncryptionService;
import io.blindnet.blindnet.internal.KeyFactory;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static io.blindnet.blindnet.internal.EncryptionConstants.*;
import static io.blindnet.blindnet.internal.EncryptionConstants.PBKDF_SHA256;

/**
 * Implementation of API used to back up and recover messages using Signal Blindnet API.
 */
class SignalBackupServiceImpl implements SignalBackupService {

    private final KeyFactory keyFactory;
    private final SignalApiClient signalApiClient;
    private final EncryptionService encryptionService;

    public SignalBackupServiceImpl(KeyFactory keyFactory,
                                   SignalApiClient signalApiClient,
                                   EncryptionService encryptionService) {

        this.keyFactory = keyFactory;
        this.signalApiClient = signalApiClient;
        this.encryptionService = encryptionService;
    }

    @Override
    public void backup(String password, boolean newBackup, List<MessageArrayWrapper> messages) {
        byte[] salt = keyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, SALT_LENGTH);
        SecretKey secretKey = keyFactory.extractAesKeyFromPassword(password.toCharArray(),
                salt,
                PBKDF_SHA256);

        List<String> encryptedMessages = new ArrayList<>();
        messages.forEach(message -> encryptedMessages.add(
                Base64.getEncoder().encodeToString(encryptionService.encrypt(secretKey, message.prepare()))));
        signalApiClient.uploadBackup(Base64.getUrlEncoder().encodeToString(salt),
                newBackup,
                encryptedMessages);
    }

    @Override
    public void backup(String password, boolean newBackup, InputStream messages) {
        byte[] salt = keyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, SALT_LENGTH);
        SecretKey secretKey = keyFactory.extractAesKeyFromPassword(password.toCharArray(),
                salt,
                PBKDF_SHA256);

        signalApiClient.uploadBackup(Base64.getUrlEncoder().encodeToString(salt),
                newBackup,
                encryptionService.encrypt(secretKey, messages));
    }

    @Override
    public List<MessageArrayWrapper> recover(String password) {
        List<String> messages = signalApiClient.fetchBackup();
        String salt = signalApiClient.fetchBackupSalt();

        SecretKey secretKey = keyFactory.extractAesKeyFromPassword(password.toCharArray(),
                Base64.getUrlDecoder().decode(salt),
                PBKDF_SHA256);
        List<MessageArrayWrapper> decryptedMessages = new ArrayList<>();
        messages.forEach(message -> decryptedMessages.add(MessageArrayWrapper.process(
                ByteBuffer.wrap(encryptionService.decrypt(secretKey, Base64.getDecoder().decode(message))))));
        return decryptedMessages;
    }

    @Override
    public InputStream recoverAsStream(String password) {
        String salt = signalApiClient.fetchBackupSalt();
        HttpURLConnection con = signalApiClient.fetchBackupAsStream();

        SecretKey secretKey = keyFactory.extractAesKeyFromPassword(password.toCharArray(),
                Base64.getUrlDecoder().decode(salt),
                PBKDF_SHA256);
        return encryptionService.decrypt(secretKey, con);
    }

}
