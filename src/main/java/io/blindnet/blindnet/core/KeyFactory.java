package io.blindnet.blindnet.core;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Objects;

/**
 * Provides methods for generation of asymmetric key pairs and symmetric keys.
 *
 * @author stefanveselinovic
 */
class KeyFactory {

    // todo check exception handling

    /**
     * Generates symmetric (secret) key.
     *
     * @param algorithm Encryption algorithm
     * @param keySize Key size
     * @return Secret key object
     * @throws GeneralSecurityException
     */
    public static SecretKey generateSecretKey(String algorithm, int keySize) throws GeneralSecurityException {
        Objects.requireNonNull(algorithm, "Algorithm name cannot be null.");
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    /**
     * Generates symmetric (secret) key spec.
     *
     * @param algorithm Encryption algorithm
     * @param keySize Key size
     * @return Secret key spec object
     * @throws GeneralSecurityException
     */
    public static SecretKeySpec generateSecretKeySpec(String algorithm, int keySize) throws GeneralSecurityException {
        Objects.requireNonNull(algorithm, "Algorithm name cannot be null.");
        return new SecretKeySpec(generateSecretKey(algorithm, keySize).getEncoded(), algorithm);
    }

    /**
     * Generates asymmetric key pair.
     *
     * @param algorithm Encryption algorithm
     * @param provider Security provider
     * @param keySize Key size
     * @return Key pair object
     * @throws GeneralSecurityException
     */
    public static KeyPair generateKeyPair(String algorithm, String provider, int keySize) throws GeneralSecurityException {
        Objects.requireNonNull(algorithm, "Algorithm name cannot be null.");
        Objects.requireNonNull(provider, "Provider name cannot be null.");
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance(algorithm, provider);
        keyPair.initialize(keySize);
        return keyPair.generateKeyPair();
    }

    /**
     * Generates asymmetric key pair.
     *
     * @param algorithm Encryption algorithm
     * @param provider Security provider
     * @param secgNotation Secg notation
     * @return Key pair object
     * @throws GeneralSecurityException
     */
    public static KeyPair generateKeyPair(String algorithm, String provider, String secgNotation) throws GeneralSecurityException {
        Objects.requireNonNull(algorithm, "Algorithm name cannot be null.");
        Objects.requireNonNull(provider, "Provider name cannot be null.");
        Objects.requireNonNull(secgNotation, "Secg notation cannot be null.");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm, provider);
        keyGen.initialize(new ECGenParameterSpec(secgNotation));
        return keyGen.generateKeyPair();
    }

}
