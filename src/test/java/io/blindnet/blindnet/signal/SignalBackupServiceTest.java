package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.core.AbstractTest;
import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.internal.EncryptionService;
import io.blindnet.blindnet.internal.KeyFactory;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.crypto.SecretKey;
import java.util.*;

import static io.blindnet.blindnet.internal.EncryptionConstants.*;
import static io.blindnet.blindnet.internal.EncryptionConstants.PBKDF_SHA256;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

public class SignalBackupServiceTest extends AbstractTest {

    private SignalBackupService signalBackupService;
    private KeyFactory keyFactory;
    private EncryptionService encryptionService;

    @Mock
    private SignalApiClient signalApiClient;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);

        keyFactory = new KeyFactory();
        encryptionService = new EncryptionService(keyFactory);

        signalBackupService = new SignalBackupServiceImpl(keyFactory,
                signalApiClient,
                encryptionService);
    }

    @Test
    public void testBackup() {
        String password = UUID.randomUUID().toString();

        List<MessageArrayWrapper> messages = new ArrayList<>();
        messages.add(createMessage());
        messages.add(createMessage());

        doNothing().when(signalApiClient).uploadBackup(any(), any(), anyList());
        assertDoesNotThrow(() -> signalBackupService.backup(password, true, messages));
    }

    @Test
    public void testRecoverMessages() {
        String password = UUID.randomUUID().toString();

        List<MessageArrayWrapper> messages = new ArrayList<>();
        messages.add(createMessage());
        messages.add(createMessage());

        byte[] salt = keyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, SALT_LENGTH);
        SecretKey secretKey = keyFactory.extractAesKeyFromPassword(password.toCharArray(),
                salt,
                PBKDF_SHA256);

        List<String> encryptedMessages = new ArrayList<>();
        messages.forEach(message -> encryptedMessages.add(Base64.getEncoder().encodeToString(encryptionService.encrypt(secretKey, message.prepare()))));

        when(signalApiClient.fetchBackupSalt())
                .thenReturn(Base64.getUrlEncoder().encodeToString(salt));
        when(signalApiClient.fetchBackup())
                .thenReturn(encryptedMessages);

        List<MessageArrayWrapper> recoveredMessages = signalBackupService.recover(password);

        assertNotNull(recoveredMessages);
        assertEquals(new String(messages.get(0).getData()), new String(recoveredMessages.get(0).getData()));
        assertEquals(new String(messages.get(1).getData()), new String(recoveredMessages.get(1).getData()));
        assertArrayEquals(messages.get(0).getMetadata().values().toArray(), recoveredMessages.get(0).getMetadata().values().toArray());
        assertArrayEquals(messages.get(0).getMetadata().keySet().toArray(), recoveredMessages.get(0).getMetadata().keySet().toArray());
        assertArrayEquals(messages.get(1).getMetadata().values().toArray(), recoveredMessages.get(1).getMetadata().values().toArray());
        assertArrayEquals(messages.get(1).getMetadata().keySet().toArray(), recoveredMessages.get(1).getMetadata().keySet().toArray());
    }

    private MessageArrayWrapper createMessage() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put(UUID.randomUUID().toString(), UUID.randomUUID().toString());
        String data = UUID.randomUUID().toString();
        return new MessageArrayWrapper(metadata, data.getBytes());
    }

}
