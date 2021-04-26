package io.blindnet.blindnet.main;

import io.blindnet.blindnet.JwtGenerator;
import io.blindnet.blindnet.MessageService;
import io.blindnet.blindnet.UserService;
import io.blindnet.blindnet.core.BlindnetClient;
import io.blindnet.blindnet.core.KeyStorageConfig;
import io.blindnet.blindnet.core.MessageServiceProvider;
import io.blindnet.blindnet.core.UserServiceProvider;
import io.blindnet.blindnet.domain.UserRegistrationResult;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.stream.Stream;

/**
 * Temporary class used for testing purposes.
 *
 * to be removed
 */
public class Main {

    public static void main(String[] args) throws GeneralSecurityException, IOException {

        System.out.println("Testing method");
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyStorageConfig keyStorageConfig = KeyStorageConfig.INSTANCE;
        keyStorageConfig.setup("/Users/stefanveselinovic/Desktop/enc.pem",
                "/Users/stefanveselinovic/Desktop/sig.pem");

        // UserRegistrationResult result = testUserRegistrationApi();
        // System.out.println("IS REGISTRATION SUCCESSFUL: " + result.isSuccessful());
        // testSigning();

//        BlindnetClient blindnetClient = new BlindnetClient();
//        Optional<PublicKeyPair> pkp = blindnetClient.fetchPublicKeys(JwtGenerator.generateJwt(), "1");
//        System.out.println("These are fetched keys");
//        System.out.println(Base64.getUrlEncoder().encodeToString(pkp.get().getSigningKey().getEncoded()));
//        System.out.println(Base64.getUrlEncoder().encodeToString(pkp.get().getEncryptionKey().getEncoded()));

//        try {
//            testFetchSymmetricKey();
//        } catch (BlindnetApiException exception) {
//            System.out.println("It is not retreieved fuck");
//        }

        testEncrypt();
    }

    private static void testEncrypt() {
        MessageService messageService = MessageServiceProvider.getInstance();
        messageService.encrypt(JwtGenerator.generateJwt(), "1", null);
    }

    private static void testFetchSymmetricKey() {
        BlindnetClient blindnetClient = new BlindnetClient();
        blindnetClient.fetchSecretKey(JwtGenerator.generateJwt(), "123", "4567");
    }

    private static UserRegistrationResult testUserRegistrationApi() throws GeneralSecurityException, IOException {
        UserService userService = UserServiceProvider.getInstance();

        JwtGenerator jwtGenerator = new JwtGenerator();
        String jwt = JwtGenerator.generateJwt();

        return userService.register(jwt);
    }

    private static void testSigning() throws GeneralSecurityException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = keyGen.generateKeyPair();

        byte[] msg = "test_string".getBytes(StandardCharsets.UTF_8);

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(kp.getPrivate());
        sig.update(msg);
        byte[] s = sig.sign();

        String encodedString = Base64.getEncoder().encodeToString(s);
        System.out.println(encodedString);
    }

}
