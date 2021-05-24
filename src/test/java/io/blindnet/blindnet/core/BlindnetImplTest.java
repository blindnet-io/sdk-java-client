package io.blindnet.blindnet.core;

import io.blindnet.blindnet.Blindnet;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class BlindnetImplTest extends AbstractTest {

    private Blindnet blindnet;

    @Mock
    private KeyEncryptionService keyEncryptionService;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        blindnet = new BlindnetImpl(keyFolderPath, TEST_JWT);
    }

    @Test
    @DisplayName("Test configuring jwt.")
    public void testSetJwt() {
        assertDoesNotThrow(() -> blindnet.setJwt(UUID.randomUUID().toString()));
    }

    @Test
    @DisplayName("Test configuring server api url.")
    public void testSetApiUrl() {
        assertDoesNotThrow(() -> blindnet.setApiUrl(UUID.randomUUID().toString()));
    }

}
