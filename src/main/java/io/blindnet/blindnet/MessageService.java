package io.blindnet.blindnet;

import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;

import java.io.InputStream;

public interface MessageService {

    byte[] encrypt(String recipientId, MessageArrayWrapper messageWrapper);

    InputStream encrypt(String recipientId, MessageStreamWrapper messageStreamWrapper);

    MessageArrayWrapper decrypt(String senderId, String recipientId, byte[] data);

    MessageStreamWrapper decrypt(String senderId, String recipientId, InputStream inputData);

}
