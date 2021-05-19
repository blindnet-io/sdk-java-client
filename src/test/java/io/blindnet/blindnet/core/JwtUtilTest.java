package io.blindnet.blindnet.core;

import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

public class JwtUtilTest extends AbstractTest {

    @Test
    @DisplayName("Test extraction of id from JWT.")
    public void testExtractUserId() {
        String userId = JwtUtil.extractUserId("eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9." +
                "eyJhcHAiOiJjNjFmMTliYS04MDBjLTRjNTItOWZiNS0zZWU3NmNvMTg5MjYiLCJ1aWQiOiJzdGVmYW4tdGVzdC0zIiwiZ2lkIj" +
                "oiZDEiLCJuYmYiOjE2MjEzNzYyMDIsImV4cCI6MTYyMTgwODIwMiwiaWF0IjoxNjIxMzc2MjAyfQ." +
                "NPR14oyyDKt1b0yCMC6Fs1rss9UIZo8K4Zxe8JGMq76jqHh1dTFOSNgE1yGRh0HRX2FOamIUOnKoo3YpOct_Dg");
        assertEquals(userId, "stefan-test-3");
    }

}
