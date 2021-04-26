package io.blindnet.blindnet;

import io.blindnet.blindnet.domain.MessageWrapper;

import java.io.InputStream;

public interface MessageService {

    byte[] encrypt(String jwt, String recipientId, MessageWrapper messageWrapper);

    byte[] encrypt(String jwt, String recipientId, InputStream metadata, InputStream data);

    MessageWrapper decrypt(String jwt, String senderId, String recipientId, byte[] data);

}
