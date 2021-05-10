package io.blindnet.blindnet.core;

import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

public class JwtUtilTest extends AbstractTest {

    @Test
    @DisplayName("Test extraction of id from JWT.")
    public void testStoreEncryptionKey() {
        String userId = JwtUtil.extractUserId(TEST_JWT);
        assertEquals(userId, "4567");
    }

}
