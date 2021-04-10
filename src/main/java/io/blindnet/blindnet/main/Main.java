package io.blindnet.blindnet.main;

import io.blindnet.blindnet.JwtGenerator;
import io.blindnet.blindnet.UserService;
import io.blindnet.blindnet.core.KeyStorageConfig;
import io.blindnet.blindnet.core.UserServiceProvider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

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
        keyStorageConfig.init("/Users/stefanveselinovic/Desktop/enc.pem",
                "/Users/stefanveselinovic/Desktop/sig.pem");

         testUserRegistrationApi();
        // testSigning();

    }

    private static void testUserRegistrationApi() throws GeneralSecurityException, IOException {
        UserService userService = UserServiceProvider.getInstance();

        JwtGenerator jwtGenerator = new JwtGenerator();
        String jwt = JwtGenerator.generateJwt();

        userService.register(jwt);
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
