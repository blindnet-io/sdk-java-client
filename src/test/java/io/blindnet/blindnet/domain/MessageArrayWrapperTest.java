package io.blindnet.blindnet.domain;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class MessageArrayWrapperTest {

    @Test
    public void testMessageWrapping() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put(UUID.randomUUID().toString(), UUID.randomUUID().toString());
        String data = UUID.randomUUID().toString();

        MessageArrayWrapper message = new MessageArrayWrapper(metadata, data.getBytes());

        byte[] wrapped = message.prepare();

        assertNotNull(wrapped);

        MessageArrayWrapper processed = MessageArrayWrapper.process(ByteBuffer.wrap(wrapped));

        assertNotNull(processed);
        assertEquals(new String(message.getData()), new String(processed.getData()));
        assertArrayEquals(message.getMetadata().keySet().toArray(), processed.getMetadata().keySet().toArray());
        assertArrayEquals(message.getMetadata().values().toArray(), processed.getMetadata().values().toArray());
    }

}
