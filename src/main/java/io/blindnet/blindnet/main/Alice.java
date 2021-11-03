package io.blindnet.blindnet.main;

import io.blindnet.blindnet.BlindnetSignal;
import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.signal.BlindnetSignalProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
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
        String BOB_USERNAME = "bob772";

        // username = alice772
        BlindnetSignal ALICE = BlindnetSignalProvider.getInstance(
                "/Users/stefanveselinovic/Desktop/blindnetdb2/",
                "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHAiOiI0MWRmMTBlYS05NjY4LTQwMTItYjRiNS04NTYyM2UyNzc5N2YiLCJ1aWQiOiJhbGljZTc3MyIsIm5iZiI6MTYzNTkzMTI4NSwiZXhwIjoxNjM1OTc0NDg1LCJpYXQiOjE2MzU5MzEyODV9.SCrwqgaz1i4gIvZah4ScGGGl1TXTMcRyvmUvmIYhEILyurWafnyBWq9bWrQXBAxG308KtxUKYpi3AjF_-AmoDg");
        if (REGISTER) {
            UserRegistrationResult aliceRegistrationResult = ALICE.register();
            System.out.println("Alice registration result is: " + aliceRegistrationResult.isSuccessful());
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



        // todo: backup messages
//        List<MessageArrayWrapper> list = new ArrayList<>();
//        Map<String, Object> metadata = new HashMap<>();
//        metadata.put("random2", "random1");
//        list.add(new MessageArrayWrapper(metadata, "data".getBytes()));
//        list.add(new MessageArrayWrapper(metadata, "data22".getBytes()));
//
//        blindnetSignal.backupMessages("randomPassword", list);
//        System.out.println("backup successful");

        // todo backup messages as stream
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

////        // todo: recover messages
//        List<MessageArrayWrapper> response = blindnetSignal.recoverMessages("randomPassword");
//        response.forEach(msg -> System.out.println(new String(msg.getData())));
//        System.out.println("Recovered successfully");


//        // todo: recover messages as stream
//        InputStream recoverMessagesAsStream = blindnetSignal.recoverMessagesAsStream("randomPassword");
//        byte[] rmetadata = new byte[8];
//        recoverMessagesAsStream.read(rmetadata);
//        byte[] rdata = new byte[4];
//        recoverMessagesAsStream.read(rdata);
//        byte[] rmetadat2 = new byte[9];
//        recoverMessagesAsStream.read(rmetadat2);
//        byte[] rdata2 = new byte[5];
//        recoverMessagesAsStream.read(rdata2);
//        System.out.println("Messages: " + new String(rmetadata) + " " + new String(rdata) + "  " + new String(rmetadat2) + " " + new String(rdata2));
//        System.out.println("Successfully recovered.");

//        SignalKeyFactory signalKeyFactory = new SignalKeyFactory();
//        SignalApiClient signalApiClient = new SignalApiClient(HttpClient.getInstance(), signalKeyFactory);
//        List<SignalPublicKeysResponse> response = signalApiClient.fetchPublicKeys("stefan-test-810");
//        System.out.println(response);
    }
}
