package io.blindnet.blindnet;

public interface KeyEncryptionService {

    void encrypt(String jwt, String password);

    void decrypt(String jwt, String password);

}
