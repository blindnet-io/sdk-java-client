package io.blindnet.blindnet.core;

import io.blindnet.blindnet.UserService;
import io.blindnet.blindnet.domain.UserRegistrationResult;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;

import java.io.IOException;

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
        userService = UserServiceProvider.getInstance();
    }

    @Test
    @DisplayName("Test user registration with successful response from Blindnet API.")
    public void testRegister_thenSuccess() throws IOException {
//        when(httpClient.post(anyString(), eq(TEST_JWT), any(byte[].class)))
//                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
//                        .withMessage(anyString())
//                        .withBody(any(byte[].class))
//                        .build());

        UserRegistrationResult result = userService.register(TEST_JWT);
        assertTrue(result.isSuccessful());
    }

}
