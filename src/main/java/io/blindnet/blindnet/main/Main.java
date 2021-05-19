package io.blindnet.blindnet.main;

import io.blindnet.blindnet.BlindnetSdkApi;
import io.blindnet.blindnet.core.BlindnetSdkApiProvider;
import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        BlindnetSdkApi api = BlindnetSdkApiProvider.getInstance();
        api.setJwt("eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHAiOiJjNjFmMTliYS04MDBjLTRjNTItOWZiNS0zZWU3NmNvMTg5MjYiLCJ1aWQiOiJzdGVmYW4tdGVzdC0zIiwiZ2lkIjoiZDEiLCJuYmYiOjE2MjEzNzYyMDIsImV4cCI6MTYyMTgwODIwMiwiaWF0IjoxNjIxMzc2MjAyfQ.NPR14oyyDKt1b0yCMC6Fs1rss9UIZo8K4Zxe8JGMq76jqHh1dTFOSNgE1yGRh0HRX2FOamIUOnKoo3YpOct_Dg");
        api.setupKeyStorage("/Users/stefanveselinovic/Desktop/enc.key",
                "/Users/stefanveselinovic/Desktop/sig.key",
                "/Users/stefanveselinovic/Desktop/publickeys");

        // api.register();
        // api.unregister();

        String msg = "random_msg";
        String metadata = "random_metadata";
        // byte[] encrypted = api.encrypt("stefan-test-2", new MessageArrayWrapper(metadata.getBytes(), msg.getBytes()));

        InputStream inputStream = api.encrypt("stefan-test-2", new MessageStreamWrapper(metadata.getBytes(), new ByteArrayInputStream(msg.getBytes())));

        // MessageArrayWrapper maw = api.decrypt("stefan-test-2", "stefan-test-3", encrypted);
        // System.out.println(Arrays.toString(maw.getData()));

        // api.encryptPrivateKeys("password123");
        // api.decryptPrivateKeys("password123");


    }
}
