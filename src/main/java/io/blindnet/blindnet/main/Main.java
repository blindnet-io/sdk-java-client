package io.blindnet.blindnet.main;

import io.blindnet.blindnet.core.SigningService;
import io.blindnet.blindnet.domain.KeyEnvelope;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

//        KeyFactory keyFactory = new KeyFactory();
//        KeyPair kp = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);
//        System.out.println("Keypair generated " + kp.getPrivate() + kp.getPublic());
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance(Ed25519_ALGORITHM, BC_PROVIDER);
//        System.out.println("generator " + kpg.getClass());
//        kpg.initialize(256);
//        KeyPair signingKeyPair = kpg.generateKeyPair();
//
//        PublicKey publicKey = keyFactory.convertToPublicKey(Base64.getUrlEncoder().encodeToString(signingKeyPair.getPublic().getEncoded()),
//                Ed25519_ALGORITHM);
//
//        PrivateKey privateKey = keyFactory.convertToPrivateKey(signingKeyPair.getPrivate().getEncoded(),
//                Ed25519_ALGORITHM);
//
//        System.out.println("Converted to pub key " + publicKey);
//        System.out.println("Converted to pub key " + signingKeyPair.getPublic());
//
//        System.out.println("Private key 1 " + privateKey);
//        System.out.println("Private key 1 " + signingKeyPair.getPrivate());

    }
}
