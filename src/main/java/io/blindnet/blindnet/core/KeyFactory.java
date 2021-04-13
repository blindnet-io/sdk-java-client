package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.KeyGenerationException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Provides methods for generation of asymmetric key pairs and symmetric keys.
 *
 * @author stefanveselinovic
 */
class KeyFactory {

    //todo consider making this non static methods

    private static final Logger LOGGER = Logger.getLogger(KeyFactory.class.getName());

    /**
     * Generates symmetric (secret) key.
     *
     * @param algorithm Encryption algorithm
     * @param keySize Key size
     * @return Secret key object
     */
    public static SecretKey generateSecretKey(String algorithm, int keySize) {
        Objects.requireNonNull(algorithm, "Algorithm name cannot be null.");

        KeyGenerator keyGenerator = initialiseGenerator(algorithm);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    /**
     * Generates symmetric (secret) key spec.
     *
     * @param algorithm Encryption algorithm
     * @param keySize Key size
     * @return Secret key spec object
     */
    public static SecretKeySpec generateSecretKeySpec(String algorithm, int keySize) {
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
     */
    public static KeyPair generateKeyPair(String algorithm, String provider, int keySize) {
        Objects.requireNonNull(algorithm, "Algorithm name cannot be null.");
        Objects.requireNonNull(provider, "Provider name cannot be null.");

        KeyPairGenerator keyPair = initialiseGenerator(algorithm, provider);
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
     */
    public static KeyPair generateKeyPair(String algorithm, String provider, String secgNotation) {
        Objects.requireNonNull(algorithm, "Algorithm name cannot be null.");
        Objects.requireNonNull(provider, "Provider name cannot be null.");
        Objects.requireNonNull(secgNotation, "Secg notation cannot be null.");

        try {
            KeyPairGenerator keyGen = initialiseGenerator(algorithm, provider);
            keyGen.initialize(new ECGenParameterSpec(secgNotation));
            return keyGen.generateKeyPair();
        } catch (InvalidAlgorithmParameterException exception) {
            String msg = "Invalid algorithm parameter. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyGenerationException(msg, exception);
        }
    }

    /**
     * Initialises KeyPair generator.
     *
     * @param algorithm Algorithm to be used.
     * @param provider Security provider.
     *
     * @return KeyPair Generator object.
     */
    private static KeyPairGenerator initialiseGenerator(String algorithm, String provider) {
        try {
            return KeyPairGenerator.getInstance(algorithm, provider);
        } catch (NoSuchAlgorithmException exception) {
            String msg = "Invalid algorithm. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyGenerationException(msg, exception);
        } catch (NoSuchProviderException exception) {
            String msg = "Invalid provider. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyGenerationException(msg, exception);
        }
    }

    /**
     * Initialises Key generator.
     *
     * @param algorithm Algorithm to be used.
     *
     * @return Key Generator object.
     */
    private static KeyGenerator initialiseGenerator(String algorithm) {
        try {
            return KeyGenerator.getInstance(algorithm);
        } catch (NoSuchAlgorithmException exception) {
            String msg = "Invalid algorithm. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyGenerationException(msg, exception);
        }
    }

}
