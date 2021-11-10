package io.blindnet.blindnet.main;

import io.blindnet.blindnet.BlindnetSignal;
import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.signal.BlindnetSignalProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.whispersystems.libsignal.InvalidKeyException;

import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.lang.String.valueOf;

public class Bob {

    public static void main(String[] args) throws InvalidKeyException {
        Security.addProvider(new BouncyCastleProvider());

        boolean REGISTER = true;
        String ALICE_USERNAME = "alice505";

        // username = bob772
        BlindnetSignal BOB = BlindnetSignalProvider.getInstance(
                "/Users/stefanveselinovic/Desktop/blindnetdb/",
                "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHAiOiI0MWRmMTBlYS05NjY4LTQwMTItYjRiNS04NTYyM2UyNzc5N2YiLCJ1aWQiOiJib2I1MDUiLCJuYmYiOjE2MzY1MjAyODIsImV4cCI6MTYzNjU2MzQ4MiwiaWF0IjoxNjM2NTIwMjgyfQ.AFNBdSl3fu5HX9XWuEzb6_tyIo5bNjwo6xFH6ViR1Mj3WR8W8v9ULKYFrxieMYkVbsTfgSC5PMJ9a6O26Y8SDw");

        if (REGISTER) {
            UserRegistrationResult bobRegistrationResult = BOB.register();
            System.out.println("Bob registration result is: " + bobRegistrationResult.isSuccessful());
            // return;
        }

        // bob reads message
        List<MessageArrayWrapper> bobDecryptionResultOne = BOB.decryptMessage(valueOf(BOB.readDeviceId()));
        System.out.println("Message from alice: " + new String(bobDecryptionResultOne.get(0).getData()));

        // bob sends message
        List<String> bobIds = new ArrayList<>();
        bobIds.add(ALICE_USERNAME);
        Map<String, Object> bobMetadata = new HashMap<>();
        bobMetadata.put("metadatakey1", "metadataobject1");
        MessageArrayWrapper heyFromBobMsg = new MessageArrayWrapper(bobMetadata, "hey from bob".getBytes());
        BOB.encryptMessage(bobIds, heyFromBobMsg);
        System.out.println("Bob sent message to alice!");

        // bob reads message
        List<MessageArrayWrapper> result2 = BOB.decryptMessage(valueOf(BOB.readDeviceId()));
        System.out.println("Message from alice: " + new String(result2.get(0).getData()));


    }
}
