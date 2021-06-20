package io.blindnet.blindnet.main;

import io.blindnet.blindnet.Blindnet;
import io.blindnet.blindnet.BlindnetSignal;
import io.blindnet.blindnet.core.BlindnetProvider;
import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;
import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.signal.BlindnetSignalProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

public class Main {

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

//        Blindnet blindnet = BlindnetProvider.getInstance("/Users/stefanveselinovic/Desktop/blindnetkeys/",
//                //"eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHAiOiJjNjFmMTliYS04MDBjLTRjNTItOWZiNS0zZWU3NmNvMTg5MjYiLCJ1aWQiOiJzdGVmYW52ZXMtdGVzdC0xIiwibmJmIjoxNjIyMTA1MjcwLCJleHAiOjE2MjI1MzcyNzAsImlhdCI6MTYyMjEwNTI3MH0.B3CTA0G8ojhVVvMBGCggh8iX4ul687UuvVUq5Dn_sSksfv72yRXDYKZ8bP7f7qqgSn5nOZbUdEOkO8b7gONLDw"
//                "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHAiOiJjNjFmMTliYS04MDBjLTRjNTItOWZiNS0zZWU3NmNvMTg5MjYiLCJ1aWQiOiJzdGVmYW4tcmFuZG9tLTgiLCJuYmYiOjE2MjM2MTI4MjMsImV4cCI6MTYyMzY1NjAyMywiaWF0IjoxNjIzNjEyODIzfQ.Ts4pn5dccs9An96lHYlc6nuXSdiarSzKyqraZGvf1lOr665OR5LdReXUU52-8JWfo7kheHp23asmttpzr2FGAQ"
//        );

//        blindnet.register();
        //blindnet.decryptPrivateKeys("password123");
        // System.out.println("Opertaion Successful.");

        // blindnet.encryptPrivateKeys("passwrd1");
        // blindnet.decryptPrivateKeys("passwrd1");

//        Map<String, Object> metadata = new HashMap<>();
//        metadata.put("key1", "value1");
//        byte[] encrypted = blindnet.encrypt("stefanves-test-1", new MessageArrayWrapper(metadata, "randomdata".getBytes()));
////
//        MessageArrayWrapper messageArrayWrapper = blindnet.decrypt("stefanves-test-2", "stefanves-test-1", encrypted);
//
//        System.out.println(messageArrayWrapper.getMetadata());
//        System.out.println(new String(messageArrayWrapper.getData()));
//
//        InputStream encryptedStream = blindnet.encrypt("stefanves-test-1",
//                new MessageStreamWrapper(new ByteArrayInputStream("random-data".getBytes())));
//
//        MessageStreamWrapper messageStreamWrapper = blindnet.decrypt("stefanves-test-2", "stefanves-test-1", encryptedStream);
//
//        byte[] b = new byte[11];
//        messageStreamWrapper.getData().read(b);
//        System.out.println("DATA JErrrrr: " + new String(b));
//        System.out.println(messageStreamWrapper.getMetadata());

        BlindnetSignal blindnetSignal = BlindnetSignalProvider.getInstance("/Users/stefanveselinovic/Desktop/blindnetkeys/",
                "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHAiOiI0MWRmMTBlYS05NjY4LTQwMTItYjRiNS04NTYyM2UyNzc5N2YiLCJ1aWQiOiJzdGVlZmFuLXRlc3QtMTAzIiwibmJmIjoxNjI0MjE4MjU4LCJleHAiOjE2MjQyNjE0NTgsImlhdCI6MTYyNDIxODI1OH0.sKyQ5Iws59M3CUVg2dOoAjkL8AfQHBIUZUn8FT5Wv8KJ_NPFYXrpZIY8tLdSXPRs71wNVF4eDhndT9TXDV7kAQ");
        // UserRegistrationResult result = blindnetSignal.register();
        // System.out.println("Result is " + result.isSuccessful());

        blindnetSignal.unregister();
    }
}
