package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.UserRegistrationResult;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import static org.junit.jupiter.api.Assertions.assertTrue;


public class UserServiceTest extends AbstractTest {

    // todo use junit 5

    private UserService userService;

    // todo use mock when http client is defined as singleton
    @Mock
    HttpClient httpClient;

    @Before
    public void setup() {
        // MockitoAnnotations.openMocks(this);
        // userService = UserServiceProvider.getInstance();
    }

    @Test
    @DisplayName("Test user registration with successful response from Blindnet API.")
    public void testRegister_thenSuccess() throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
//        when(httpClient.post(anyString(), eq(TEST_JWT), any(byte[].class)))
//                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
//                        .withMessage(anyString())
//                        .withBody(any(byte[].class))
//                        .build());

        UserRegistrationResult result = userService.register();
        assertTrue(result.isSuccessful());
    }

}
