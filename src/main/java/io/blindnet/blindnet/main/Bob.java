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

        boolean REGISTER = false;
        String ALICE_USERNAME = "alice2000";

        // username = bob2000
        BlindnetSignal BOB = BlindnetSignalProvider.getInstance(
                "/Users/stefanveselinovic/Desktop/blindnetdb/",
                "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHAiOiI0MWRmMTBlYS05NjY4LTQwMTItYjRiNS04NTYyM2UyNzc5N2YiLCJ1aWQiOiJib2IyMDAwIiwibmJmIjoxNjM5NTEzMDgwLCJleHAiOjE2Mzk1NTYyODAsImlhdCI6MTYzOTUxMzA4MH0.i6KmBQ-LfmaywBsK7my4Razips2UhKvdlWIM3a8TwuYcV4kiiKCK_4UcspvvvSp4B261D3d2aAdslaDgeeb1Cg");

        if (REGISTER) {
            UserRegistrationResult bobRegistrationResult = BOB.register();
            System.out.println("Bob registration result is: " + bobRegistrationResult.isSuccessful());
             return;
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
