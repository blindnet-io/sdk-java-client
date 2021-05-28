package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.KeyConstructionException;
import io.blindnet.blindnet.exception.KeyGenerationException;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.json.JSONObject;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.*;
import java.util.Base64;

import static io.blindnet.blindnet.core.EncryptionConstants.*;
import static java.util.Objects.requireNonNull;

/**
 * Provides API for operations with asymmetric key pairs and symmetric keys.
 */
class KeyFactory {

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
            throw new KeyGenerationException("Error while generating secure random.");
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
            throw new KeyGenerationException("Error while generating AES key from password.");
        }
    }

    /**
     * Extracts a RSA public key from private key.
     *
     * @param privateKey a private key from which the public key is extracted.
     * @return a public key object.
     */
    public PublicKey extractRsaPublicKey(PrivateKey privateKey) {
        try {
            RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey;
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaPrivateCrtKey.getModulus(),
                    rsaPrivateCrtKey.getPublicExponent());
            java.security.KeyFactory keyFactory = initialiseKeyFactory(RSA_ALGORITHM);
            return keyFactory.generatePublic(publicKeySpec);

        } catch (GeneralSecurityException exception) {
            throw new KeyGenerationException("Error during extraction of public key from a private key.");
        }
    }

    /**
     * Converts Base64 encoded public key to the public key object.
     *
     * @param base64PK a Base64 encoded public key.
     * @return a public key object.
     */
    public PublicKey convertToPublicKey(String base64PK, String algorithm) {
        try {
            java.security.KeyFactory keyFactory = initialiseKeyFactory(algorithm);

            if (algorithm.equals(Ed25519_ALGORITHM)) {
                SubjectPublicKeyInfo pubKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                        Base64.getDecoder().decode(base64PK));
                return keyFactory.generatePublic(new X509EncodedKeySpec(pubKeyInfo.getEncoded()));
            } else {
                SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(Base64.getDecoder().decode(base64PK.getBytes()));
                RSAKeyParameters keyParameter = (RSAKeyParameters) PublicKeyFactory.createKey(publicKeyInfo.parsePublicKey().getEncoded());
                return keyFactory.generatePublic(new RSAPublicKeySpec(keyParameter.getModulus(), keyParameter.getExponent()));
            }
        } catch (GeneralSecurityException | IOException exception) {
            throw new KeyConstructionException("Error while converting public key.");
        }
    }

    /**
     * Converts private key represented as byte array to a Ed25519 private key object.
     *
     * @param pkBytes a byte array private key representation.
     * @return a private key object.
     */
    public PrivateKey convertToEd25519PrivateKey(byte[] pkBytes) {

        try {
            PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                    new DEROctetString(pkBytes));
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
            java.security.KeyFactory kf = initialiseKeyFactory(Ed25519_ALGORITHM);
            return kf.generatePrivate(pkcs8KeySpec);
        } catch (GeneralSecurityException | IOException exception) {
            throw new KeyConstructionException("Error while converting private key.");
        }
    }

    /**
     * Converts RSA private key from jwk format to private key object.
     *
     * @param rsaJwk a rsa private key in jwk format.
     * @return a private key object.
     */
    public PrivateKey convertToRsaPrivateKey(JSONObject rsaJwk) {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        RSAPrivateCrtKeySpec rsaPrivateCrtKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger(decoder.decode(rsaJwk.getString("n"))),
                new BigInteger(decoder.decode(rsaJwk.getString("e"))),
                new BigInteger(decoder.decode(rsaJwk.getString("d"))),
                new BigInteger(decoder.decode(rsaJwk.getString("p"))),
                new BigInteger(decoder.decode(rsaJwk.getString("q"))),
                new BigInteger(decoder.decode(rsaJwk.getString("dp"))),
                new BigInteger(decoder.decode(rsaJwk.getString("dq"))),
                new BigInteger(decoder.decode(rsaJwk.getString("qi"))));
        try {
            java.security.KeyFactory kf = initialiseKeyFactory(RSA_ALGORITHM);
            return kf.generatePrivate(rsaPrivateCrtKeySpec);
        } catch (GeneralSecurityException exception) {
            throw new KeyConstructionException("Error while converting rsa private key.");
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
            throw new KeyGenerationException("Invalid algorithm.");
        } catch (NoSuchProviderException exception) {
            throw new KeyGenerationException("Invalid provider.");
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
            throw new KeyGenerationException("Invalid algorithm.");
        }
    }

    /**
     * Initialises key factory.
     *
     * @param algorithm an algorithm to be used for key factory.
     * @return a key factory object.
     */
    private java.security.KeyFactory initialiseKeyFactory(String algorithm) {
        try {
            return java.security.KeyFactory.getInstance(algorithm, BC_PROVIDER);
        } catch (GeneralSecurityException exception) {
            throw new KeyConstructionException("Error initialising key factory.");
        }
    }

}
