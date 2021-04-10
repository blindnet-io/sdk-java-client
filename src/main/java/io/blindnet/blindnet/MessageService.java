package io.blindnet.blindnet;

import java.security.GeneralSecurityException;

public interface MessageService {

    void encrypt(String jwt, int recipientId, String data, String metadata) throws GeneralSecurityException;

    void decrypt(String jwt, int senderId, int recipientId, String data);

}
