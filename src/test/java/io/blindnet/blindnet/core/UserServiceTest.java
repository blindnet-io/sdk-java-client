package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.UserRegistrationResult;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;


public class UserServiceTest extends AbstractTest {

    private UserService userService;

    @Mock
    private ApiClient apiClient;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        KeyStorage keyStorage = KeyStorage.getInstance();
        KeyFactory keyFactory = new KeyFactory();
        SigningService signingService = new SigningService();

        userService = new UserServiceImpl(keyStorage,
                keyFactory,
                signingService,
                apiClient);
    }

    @Test
    @DisplayName("Test user registration.")
    public void testRegister() {
        when(apiClient.register(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new UserRegistrationResult(true, "random_string"));

        UserRegistrationResult result = userService.register();

        assertNotNull(result);
        assertTrue(result.isSuccessful());
    }

    @Test
    @DisplayName("Test unregister.")
    public void testUnregister() {
        doNothing().when(apiClient).unregister();

        assertDoesNotThrow(() -> userService.unregister());
    }

}
