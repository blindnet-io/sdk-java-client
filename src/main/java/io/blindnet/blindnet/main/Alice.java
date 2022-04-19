package io.blindnet.blindnet.main;

import io.blindnet.blindnet.BlindnetSignal;
import io.blindnet.blindnet.domain.message.MessageArrayWrapper;
import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.signal.BlindnetSignalProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.lang.String.valueOf;

public class Alice {

    // used for testing purposes during development
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // test sending of messages (will be improved)
        // use  break points to simulate flow
        // 1. both users need to be registered
        // 2. start alice in debug mode
        // 3. start bob in debug mode
        // 4. alice sends message
        // 5. bob reads message
        // 6. bob responds
        // 7. alice reads message
        // 8. alice responds
        // 9. bob reads message
        boolean REGISTER = true;
        String BOB_USERNAME = "bob777";

        BlindnetSignal ALICE = BlindnetSignalProvider.getInstance(
                "/Users/stefanveselinovic/Desktop/blindnetdb2/",
                "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHAiOiI0MWRmMTBlYS05NjY4LTQwMTItYjRiNS04NTYyM2UyNzc5N2YiLCJ1aWQiOiJhbGljZSIsIm5iZiI6MTY1MDQwOTc1NSwiZXhwIjoxNjUwNDUyOTU1LCJpYXQiOjE2NTA0MDk3NTV9.ze_jH3ORpO2Sqvux12rA4VnR-XGN0jNYwD--Kt9qQtF2bAWD0JgWhPp7f2RcgPscVkNpKOAMgFHMaYYbGMMSBg");
        if (REGISTER) {
            UserRegistrationResult aliceRegistrationResult = ALICE.register();
            System.out.println("Alice registration result is: " + aliceRegistrationResult.isSuccessful());
            // return;
        }

        // alice sends message
        List<String> aliceIds = new ArrayList<>();
        aliceIds.add(BOB_USERNAME);
        Map<String, Object> aliceMetadata = new HashMap<>();
        aliceMetadata.put("metadatakey1", "metadataobject1");
        MessageArrayWrapper heyFromAliceMsg = new MessageArrayWrapper(aliceMetadata, "Hello from alice".getBytes());
        ALICE.encryptMessage(aliceIds, heyFromAliceMsg);
        System.out.println("Alice sent message to bob!");

        // alice reads message
        List<MessageArrayWrapper> result = ALICE.decryptMessage(valueOf(ALICE.readDeviceId()));
        System.out.println("Message from bob: " + new String(result.get(0).getData()));

        // alice sends message
        MessageArrayWrapper howAreYouFromAliceMsg = new MessageArrayWrapper(aliceMetadata, "how are u bob?".getBytes());
        ALICE.encryptMessage(aliceIds, howAreYouFromAliceMsg);
        System.out.println("ENCRYPTED MESSAGES OLE OLE");



//        BACKUP MESSAGES
//        List<MessageArrayWrapper> list = new ArrayList<>();
//        Map<String, Object> metadata = new HashMap<>();
//        metadata.put("random2", "random1");
//        list.add(new MessageArrayWrapper(metadata, "data".getBytes()));
//        list.add(new MessageArrayWrapper(metadata, "data22".getBytes()));
//
//        blindnetSignal.backupMessages("randomPassword", list);
//        System.out.println("backup successful");

//        BACKUP MESSAGES AS STREAM
//        String metadata = "metarara";
//        String data = "gari";
//        String metadata2 = "metaprso2";
//        String data2 = "dajr2";
//
//        InputStream messages = new ByteArrayInputStream(ByteBuffer
//                .allocate(metadata.getBytes().length + data.getBytes().length + metadata2.getBytes().length + data2.getBytes().length)
//                .put(metadata.getBytes())
//                .put(data.getBytes())
//                .put(metadata2.getBytes())
//                .put(data2.getBytes())
//                .array());
//
//        blindnetSignal.backupMessages("randomPassword", messages);
//

////      RECOVER MESSAGES
//        List<MessageArrayWrapper> response = blindnetSignal.recoverMessages("randomPassword");
//        response.forEach(msg -> System.out.println(new String(msg.getData())));
//        System.out.println("Recovered successfully");


    }
}
