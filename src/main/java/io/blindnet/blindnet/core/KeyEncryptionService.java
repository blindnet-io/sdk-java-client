package io.blindnet.blindnet.core;

/**
 * Provides API for encryption and decryption of user private keys.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
interface KeyEncryptionService {

    /**
     * Encrypts user's private keys and sends them to Blindnet API.
     *
     * @param password a password phrase used for encryption.
     */
    void encrypt(String password);

    /**
     * Retrieves user's private keys from Blindnet API and decrypts them.
     *
     * @param password a password phrase used for decryption.
     */
    void decrypt(String password);

}
