package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.MessageWrapper;
import io.blindnet.blindnet.exception.JwtException;
import org.json.JSONObject;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
import static java.util.Objects.requireNonNull;

/**
 * todo javadoc
 * todo package view not public
 *
 * @author stefanveselinovic
 */
public class EncryptionService {

    private static final Logger LOGGER = Logger.getLogger(EncryptionService.class.getName());

    /**
     * todo javadoc
     *
     * @param secretKey
     * @param messageWrapper
     * @return
     */
    public byte[] encryptMessage(SecretKey secretKey, MessageWrapper messageWrapper) {

        byte[] metadataLengthBA = ByteBuffer.allocate(4).putInt(messageWrapper.getMetadata().length).array();

        // data to be encrypted -> metadata length + metadata + data
        byte[] data = ByteBuffer.allocate(metadataLengthBA.length +
                messageWrapper.getMetadata().length +
                messageWrapper.getData().length)
                .put(metadataLengthBA)
                .put(messageWrapper.getMetadata())
                .put(messageWrapper.getData())
                .array();

        return encrypt(secretKey, data);
    }

    public MessageWrapper decryptMessage(SecretKey secretKey, byte[] data) {
        ByteBuffer decryptedDataWrapper = ByteBuffer.wrap(
                requireNonNull(decrypt(secretKey, data)));

        byte[] decryptedMetadataLengthBA = new byte[4];
        decryptedDataWrapper.get(decryptedMetadataLengthBA);
        int metadataLength = ByteBuffer.wrap(decryptedMetadataLengthBA).getInt();

        byte[] decryptedMetadata = new byte[metadataLength];
        decryptedDataWrapper.get(decryptedMetadata);

        byte[] decryptedData = new byte[decryptedDataWrapper.remaining()];
        decryptedDataWrapper.get(decryptedData);

        return new MessageWrapper(decryptedMetadata, decryptedData);
    }

    /**
     * Signs data using provided private key.
     *
     * @param data             data to be signed.
     * @param privateKey       Private key used for signing.
     * @param signingAlgorithm Algorithm to be used for signing.
     * @return Base64 signed JWT.
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public String sign(String data, PrivateKey privateKey, String signingAlgorithm) throws InvalidKeyException,
            SignatureException {

        return sign(data.getBytes(), privateKey, signingAlgorithm);
    }

    /**
     * todo javadoc
     *
     * @param object
     * @param privateKey
     * @param signingAlgorithm
     * @return
     * @throws InvalidKeyException
     * @throws IOException
     * @throws SignatureException
     */
    public String sign(Object object, PrivateKey privateKey, String signingAlgorithm) throws InvalidKeyException,
            IOException,
            SignatureException {

        JSONObject jsonObject = new JSONObject(object);
        return sign(jsonObject.toString().getBytes(), privateKey, signingAlgorithm);
    }

    /**
     * todo javadoc
     *
     * @param data
     * @param privateKey
     * @param signingAlgorithm
     * @return
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public String sign(byte[] data, PrivateKey privateKey, String signingAlgorithm) throws InvalidKeyException,
            SignatureException {

        Signature signature = createSignature(signingAlgorithm);
        signature.initSign(privateKey);
        signature.update(data);
        byte[] signatureValue = signature.sign();

        return Base64.getUrlEncoder().encodeToString(signatureValue);
    }

    /**
     * todo javadoc
     *
     * @param signedObject
     * @param base64Signature
     * @param publicKey
     * @param signingAlgorithm
     * @return
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public boolean verify(Object signedObject,
                          String base64Signature,
                          PublicKey publicKey,
                          String signingAlgorithm) throws InvalidKeyException,
            SignatureException {

        Signature signature = createSignature(signingAlgorithm);
        signature.initVerify(publicKey);

        JSONObject jsonObject = new JSONObject(signedObject);
        signature.update(jsonObject.toString().getBytes());

        return signature.verify(Base64.getUrlDecoder().decode(base64Signature));
    }

    /**
     * todo javadoc
     *
     * @param secretKey
     * @param publicKey
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws IllegalBlockSizeException
     */
    public byte[] wrap(SecretKey secretKey, PublicKey publicKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            NoSuchProviderException,
            IllegalBlockSizeException {

        // todo check padding, check oaep parameters specification
        Cipher c = Cipher.getInstance("RSA/NONE/OAEPPadding", BC_PROVIDER);
        c.init(Cipher.WRAP_MODE, publicKey);
//        c.init(Cipher.WRAP_MODE, publicKey,
//                new OAEPParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"),
//                        PSource.PSpecified.DEFAULT));
        return c.wrap(secretKey);
    }

    /**
     * todo javadoc
     *
     * @param wrappedKey
     * @param privateKey
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    public Key unwrap(byte[] wrappedKey, PrivateKey privateKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException {

        // todo check algs
        Cipher c = Cipher.getInstance("RSA/NONE/OAEPPadding", BC_PROVIDER);
        c.init(Cipher.UNWRAP_MODE, privateKey);
        return c.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }

    /**
     * todo javadoc and exception handling
     * @param secretKey
     * @param data
     * @return
     */
    public byte[] encrypt(SecretKey secretKey, byte[] data) {
        try {
            byte[] iv = KeyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, GCM_IV_LENGTH);
            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_T_LENGTH, iv));

            byte[] encryptedData = cipher.doFinal(data);

            return ByteBuffer.allocate(iv.length + encryptedData.length)
                    .put(iv)
                    .put(encryptedData)
                    .array();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * todo javadoc and exception handling
     *
     * @param secretKey
     * @param data
     * @return
     */
    public byte[] decrypt(SecretKey secretKey, byte[] data) {

        try {
            ByteBuffer encryptedDataWrapper = ByteBuffer.wrap(data);
            byte[] iv = new byte[GCM_IV_LENGTH];
            encryptedDataWrapper.get(iv);

            byte[] encryptedData = new byte[encryptedDataWrapper.remaining()];
            encryptedDataWrapper.get(encryptedData);

            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_T_LENGTH, iv));

            return cipher.doFinal(encryptedData);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return new byte[4];
    }

    /**
     * Creates Signature instance based on provided algorithm.
     *
     * @param signingAlgorithm Signing algorithm used to create signature.
     * @return Signature object.
     */
    private Signature createSignature(String signingAlgorithm) {
        try {
            return Signature.getInstance(signingAlgorithm);
        } catch (NoSuchAlgorithmException exception) {
            String msg = "Unable to create a signature instance. Invalid signature algorithm." + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg, exception);
            throw new JwtException(msg, exception);
        }
    }

}
