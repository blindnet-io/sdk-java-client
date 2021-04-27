package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.JwtException;
import io.blindnet.blindnet.exception.KeyConstructionException;
import io.blindnet.blindnet.exception.KeyGenerationException;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;

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
     * @param keySize   Key size
     * @return Secret key object
     */
    public static SecretKey generateSecretKey(String algorithm, int keySize) {
        requireNonNull(algorithm, "Algorithm name cannot be null.");

        KeyGenerator keyGenerator = initialiseGenerator(algorithm);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    /**
     * Generates symmetric (secret) key spec.
     *
     * @param algorithm Encryption algorithm
     * @param keySize   Key size
     * @return Secret key spec object
     */
    public static SecretKeySpec generateSecretKeySpec(String algorithm, int keySize) {
        requireNonNull(algorithm, "Algorithm name cannot be null.");

        return new SecretKeySpec(generateSecretKey(algorithm, keySize).getEncoded(), algorithm);
    }

    /**
     * todo javadoc
     *
     * @param size
     * @param algorithm
     * @param provider
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static byte[] generateRandom(String algorithm, String provider, int size) throws NoSuchAlgorithmException,
            NoSuchProviderException {

        byte[] iv = new byte[size];
        SecureRandom.getInstance(algorithm, provider).nextBytes(iv);
        return iv;
    }

    /**
     * Generates asymmetric key pair.
     *
     * @param algorithm Encryption algorithm
     * @param provider  Security provider
     * @param keySize   Key size
     * @return Key pair object
     */
    public static KeyPair generateKeyPair(String algorithm, String provider, int keySize) {
        requireNonNull(algorithm, "Algorithm name cannot be null.");
        requireNonNull(provider, "Provider name cannot be null.");

        KeyPairGenerator keyPair = initialiseGenerator(algorithm, provider);
        keyPair.initialize(keySize);
        return keyPair.generateKeyPair();
    }

    /**
     * Generates asymmetric key pair.
     *
     * @param algorithm    Encryption algorithm
     * @param provider     Security provider
     * @param secgNotation Secg notation
     * @return Key pair object
     */
    public static KeyPair generateKeyPair(String algorithm, String provider, String secgNotation) {
        requireNonNull(algorithm, "Algorithm name cannot be null.");
        requireNonNull(provider, "Provider name cannot be null.");
        requireNonNull(secgNotation, "Secg notation parameter cannot be null.");

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
     * todo javadoc
     * @param password
     * @param salt
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static SecretKey getAESKeyFromPassword(char[] password,
                                                  byte[] salt,
                                                  String keyFactoryAlgorithm,
                                                  String algorithm,
                                                  int keyLength,
                                                  int iterationCount)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance(keyFactoryAlgorithm);
        KeySpec spec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), algorithm);
    }


    /**
     *
     */
    public static PublicKey extractPublicKey(PrivateKey privateKey,
                                             String algorithm,
                                             String provider,
                                             String secgNotation) {

        try {
            ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance(algorithm, provider);
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(secgNotation);

            ECPoint Q = ecSpec.getG().multiply(ecPrivateKey.getD());
            byte[] publicDerBytes = Q.getEncoded(false);

            ECPoint point = ecSpec.getCurve().decodePoint(publicDerBytes);
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
            return keyFactory.generatePublic(pubSpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * todo javadoc exception handling
     */
    public static PublicKey extractPublicKey(PrivateKey privateKey,
                                             String algorithm,
                                             String provider) {

        RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey;
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaPrivateCrtKey.getModulus(),
                rsaPrivateCrtKey.getPublicExponent());

        try {
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance(algorithm, provider);
            return keyFactory.generatePublic(publicKeySpec);

        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        //todo remove
        return null;
    }

    /**
     * Converts public key Base64 encoded to the Public Key Object.
     *
     * @param base64PK Base64 encoded Public Key.
     * @return Public Key object.
     */
    public static PublicKey convertToPublicKey(String base64PK, String algorithm) {

        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(
                Base64.getUrlDecoder()
                        .decode(base64PK.getBytes()));
        try {
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance(algorithm);
            return keyFactory.generatePublic(X509publicKey);
        } catch (GeneralSecurityException exception) {
            String msg = "Error while converting Public Key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyConstructionException(msg, exception);
        }
    }

    public static PrivateKey convertToPrivateKey(byte[] pkBytes, String algorithm) throws NoSuchAlgorithmException,
            InvalidKeySpecException {

        java.security.KeyFactory kf = java.security.KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(pkBytes));
    }

    /**
     * Initialises KeyPair generator.
     *
     * @param algorithm Algorithm to be used.
     * @param provider  Security provider.
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
