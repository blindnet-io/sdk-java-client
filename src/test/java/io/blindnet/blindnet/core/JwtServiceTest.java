package io.blindnet.blindnet.core;

import io.blindnet.blindnet.JwtGenerator;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

public class JwtServiceTest {

    private JwtService jwtService;

    @Before
    public void setUp() {
        jwtService = new JwtService();
    }

    @Test
    @DisplayName("Test extraction of id from JWT.")
    public void testStoreEncryptionKey() {
        String jwt = JwtGenerator.generateJwt();
        String userId = jwtService.extractUserId(jwt);
        assertEquals(userId, "4567");
    }

}
