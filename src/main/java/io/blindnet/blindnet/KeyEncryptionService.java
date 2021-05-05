package io.blindnet.blindnet;

public interface KeyEncryptionService {

    void encrypt(String password);

    void decrypt(String password);

}
