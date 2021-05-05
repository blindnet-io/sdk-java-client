package io.blindnet.blindnet.core;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class HttpClientTest {

    private HttpClient httpClient;

    @Before
    public void setUp() {
        httpClient = HttpClient.getInstance();
    }

    @Test
    public void testPost() {
        String jsonInputString = "{\n" +
                "   \"signedJwt\": \"signedjwt\",\n" +
                "   \"encryptedPrivateEncryptionKey\": \"encdedkey\",\n" +
                "   \"encryptedPrivateSigningKey\": \"encedsignke\",\n" +
                "}";
        byte[] body = jsonInputString.getBytes(StandardCharsets.UTF_8);
        httpClient.post("https://38d53445-1473-4da0-9ab6-f34a24412c93.mock.pstmn.io/api/v1/users", "jwt", body);
        assertTrue(true);
    }

}
