package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.KeyConstructionException;
import io.blindnet.blindnet.exception.KeyGenerationException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
import static java.util.Objects.requireNonNull;

/**
 * Provides API for operations with asymmetric key pairs and symmetric keys.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
class KeyFactory {

    private static final Logger LOGGER = Logger.getLogger(KeyFactory.class.getName());

    /**
     * Generates secure random byte array.
     *
     * @param size      a size of the byte array.
     * @param algorithm an algorithm used for generation.
     * @param provider  a security provider.
     * @return a byte array of random values.
     */
    public byte[] generateRandom(String algorithm, String provider, int size) {
        requireNonNull(algorithm, "Algorithm name cannot be null.");
        requireNonNull(provider, "Provider name cannot be null.");

        try {
            byte[] iv = new byte[size];
            SecureRandom.getInstance(algorithm, provider).nextBytes(iv);
            return iv;
        } catch (GeneralSecurityException exception) {
            String msg = "Error while generating secure random. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyGenerationException(msg, exception);
        }
    }

    /**
     * Generates symmetric (secret) key.
     *
     * @param algorithm an encryption algorithm.
     * @param keySize   a key size.
     * @return a secret key object.
     */
    public SecretKey generateSecretKey(String algorithm, int keySize) {
        requireNonNull(algorithm, "Algorithm name cannot be null.");

        KeyGenerator keyGenerator = initialiseGenerator(algorithm);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    /**
     * Generates asymmetric key pair.
     *
     * @param algorithm an encryption algorithm.
     * @param provider  a security provider.
     * @param keySize   a key size.
     * @return a key pair object.
     */
    public KeyPair generateKeyPair(String algorithm, String provider, int keySize) {
        requireNonNull(algorithm, "Algorithm name cannot be null.");
        requireNonNull(provider, "Provider name cannot be null.");

        KeyPairGenerator keyPairGenerator = initialiseGenerator(algorithm, provider);
        if (keySize > 0) keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Generates AES secret key based on provided password.
     *
     * @param password a password phrase used to generate the key.
     * @param salt     a salt.
     * @return a secret key object.
     */
    public SecretKey extractAesKeyFromPassword(char[] password,
                                               byte[] salt,
                                               String keyFactoryAlgorithm) {
        requireNonNull(password, "Password phrase cannot be null.");
        requireNonNull(salt, "Salt cannot be null.");
        requireNonNull(keyFactoryAlgorithm, "Key factory algorithm cannot be null.");

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(keyFactoryAlgorithm);
            KeySpec spec = new PBEKeySpec(password, salt, AES_KEY_ITERATION_COUNT, AES_KEY_SIZE);
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), AES_ALGORITHM);
        } catch (GeneralSecurityException exception) {
            String msg = "Error while generating AES key from password. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyGenerationException(msg, exception);
        }
    }

    /**
     * Extracts a RSA public key from private key.
     *
     * @param privateKey a private key from which the public key is extracted.
     * @return a public key object.
     */
    public PublicKey extractRsaPublicKey(PrivateKey privateKey) {

        RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey;
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaPrivateCrtKey.getModulus(),
                rsaPrivateCrtKey.getPublicExponent());

        try {
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance(RSA_ALGORITHM, BC_PROVIDER);
            return keyFactory.generatePublic(publicKeySpec);

        } catch (GeneralSecurityException exception) {
            String msg = "Error during extraction of public key from a private key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyGenerationException(msg, exception);
        }
    }

    /**
     * Converts Base64 encoded public key to the public key object.
     *
     * @param base64PK a Base64 encoded public key.
     * @return a public key object.
     */
    public PublicKey convertToPublicKey(String base64PK, String algorithm) {

        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(
                Base64.getUrlDecoder()
                        .decode(base64PK.getBytes()));
        try {
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance(algorithm);
            return keyFactory.generatePublic(X509publicKey);
        } catch (GeneralSecurityException exception) {
            String msg = "Error while converting public key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyConstructionException(msg, exception);
        }
    }

    /**
     * Converts private key represented as byte array to a private key object.
     *
     * @param pkBytes   a byte array private key representation.
     * @param algorithm an algorithm used to create the private key.
     * @return a private key object.
     */
    public PrivateKey convertToPrivateKey(byte[] pkBytes, String algorithm) {

        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance(algorithm);
            return kf.generatePrivate(new PKCS8EncodedKeySpec(pkBytes));
        } catch (GeneralSecurityException exception) {
            String msg = "Error while converting private key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyConstructionException(msg, exception);
        }
    }

    /**
     * Initialises key pair generator.
     *
     * @param algorithm an algorithm to be used.
     * @param provider  a security provider.
     * @return a key pair generator object.
     */
    private KeyPairGenerator initialiseGenerator(String algorithm, String provider) {
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
     * Initialises key generator.
     *
     * @param algorithm an algorithm to be used.
     * @return a key generator object.
     */
    private KeyGenerator initialiseGenerator(String algorithm) {
        try {
            return KeyGenerator.getInstance(algorithm);
        } catch (NoSuchAlgorithmException exception) {
            String msg = "Invalid algorithm. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyGenerationException(msg, exception);
        }
    }

}
