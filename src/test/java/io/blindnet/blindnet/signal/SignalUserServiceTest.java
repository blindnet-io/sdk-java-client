package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.internal.KeyFactory;
import io.blindnet.blindnet.internal.SigningService;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

public class SignalUserServiceTest extends SignalAbstractTest {

    private SignalUserService signalUserService;

    @Mock
    private SignalApiClient signalApiClient;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        KeyFactory keyFactory = new KeyFactory();
        SignalKeyFactory signalKeyFactory = new SignalKeyFactory();
        SigningService signingService = new SigningService();
        //signalApiClient = new SignalApiClient(HttpClient.getInstance(), signalKeyFactory);

        SignalSignedPreKeyDatabase signalSignedPreKeyDatabase = new SignalSignedPreKeyDatabase();
        SignalPreKeyDatabase signalPreKeyDatabase = new SignalPreKeyDatabase();
        SignalIdentityDatabase signalIdentityDatabase = new SignalIdentityDatabase();
        SignalPreKeyStore signalPreKeyStore = new SignalPreKeyStore(signalPreKeyDatabase,
                signalIdentityDatabase,
                signalApiClient,
                signalKeyFactory);
        SignalSignedPreKeyStore signalSignedPreKeyStore = new SignalSignedPreKeyStore(signalSignedPreKeyDatabase);
        SignalIdentityKeyStore signalIdentityKeyStore = new SignalIdentityKeyStore(signalIdentityDatabase);

        signalUserService = new SignalUserServiceImpl(keyFactory,
                signalKeyFactory,
                signingService,
                signalApiClient,
                signalIdentityKeyStore,
                signalSignedPreKeyStore,
                signalPreKeyStore);
    }

    @Test
    @DisplayName("Test registration of Signal user.")
    public void testRegister() {
        String msg = "Registration successful";
        when(signalApiClient.register(any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new UserRegistrationResult(true, msg));

        UserRegistrationResult userRegistrationResult = signalUserService.register();

        assertTrue(userRegistrationResult.isSuccessful());
        assertEquals(userRegistrationResult.getMessage(), msg);
    }

    @Test
    @DisplayName("Test unregistration of Signal user.")
    public void testUnregister() {
        doNothing().when(signalApiClient).unregister();
        assertDoesNotThrow(() -> signalUserService.unregister());
    }

}
