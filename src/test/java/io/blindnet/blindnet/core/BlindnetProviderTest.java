package io.blindnet.blindnet.core;

import io.blindnet.blindnet.Blindnet;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class BlindnetProviderTest extends AbstractTest {

    @Test
    @DisplayName("Test creating default blindnet implementation.")
    public void testGetInstance() {
        Blindnet blindnet = BlindnetProvider.getInstance(keyFolderPath, TEST_TOKEN);

        assertNotNull(blindnet);
    }
}
