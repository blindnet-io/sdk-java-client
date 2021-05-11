package io.blindnet.blindnet.core;

import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

public class JwtUtilTest extends AbstractTest {

    @Test
    @DisplayName("Test extraction of id from JWT.")
    public void testExtractUserId() {
        String userId = JwtUtil.extractUserId("eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9." +
                "eyJhcHBfaWQiOiJjNjFmMTliYS04MDBjLTRjNTItOWZiNS0zZWU3NmNvMTg5MjYiLCJ1c2VyX2lkIjoiMTIzNCIsInVzZXJfaWRzIjoiYWJjIi" +
                "widXNlcl9ncm91cF9pZCI6IjU2NzgiLCJuYmYiOjE2MjA3MzU3NTUsImV4cCI6MTYyMTE2Nzc1NSwiaWF0IjoxNjIwNzM1NzU1fQ." +
                "fWwg7iaa1ab3DmH6bKEyqjDV9oUHP13v4oz3DX2NFhq1VcDrPIIhQaflBN6E9efAnxcfE7RISZQhjIv-o5t4Dg");
        assertEquals(userId, "1234");
    }

}
