package io.blindnet.blindnet.main;

import io.blindnet.blindnet.KeyEncryptionService;
import io.blindnet.blindnet.MessageService;
import io.blindnet.blindnet.UserService;
import io.blindnet.blindnet.core.*;
import io.blindnet.blindnet.domain.KeyEnvelope;
import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.UserRegistrationResult;
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

        KeyStorageConfig.INSTANCE.setup("/Users/stefanveselinovic/Desktop/enc.key",
                "/Users/stefanveselinovic/Desktop/sig.key",
                "/Users/stefanveselinovic/Desktop/");
        JwtConfig.INSTANCE.setup("eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHBfaWQiOiJjNjFmMTliYS04MDBjLTRjNTItOWZiNS0zZWU3NmNvMTg5MjYiLCJ1c2VyX2lkIjoiMTIzNCIsInVzZXJfaWRzIjoiYWJjIiwidXNlcl9ncm91cF9pZCI6IjU2NzgiLCJuYmYiOjE2MjA3NjYxNTYsImV4cCI6MTYyMTE5ODE1NiwiaWF0IjoxNjIwNzY2MTU2fQ.Unpvvgb1YqstNZZaetA2qDeAiboMukI_eVB4F8qKLr6ySEPvYYOKVYG9LQppz1jCcJz6Irb08yGsh-l-IgLmAg");

        UserService userService = UserServiceProvider.getInstance();
        UserRegistrationResult userRegistrationResult = userService.register();
        System.out.println(userRegistrationResult.getMessage());
        System.out.println(userRegistrationResult.isSuccessful());

        // userService.unregister();

        MessageService messageService = MessageServiceProvider.getInstance();
       // messageService.encrypt("marko-test-0", new MessageArrayWrapper("metadata".getBytes(), "data".getBytes()));

        KeyEncryptionService keyEncryptionService = KeyEncryptionServiceProvider.getInstance();
        // keyEncryptionService.encrypt("password123");

        // keyEncryptionService.decrypt("password123");
    }
}
