package io.blindnet.blindnet.main;

import io.blindnet.blindnet.BlindnetSignal;
import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.internal.DatabaseService;
import io.blindnet.blindnet.signal.SignalIdentityDatabase;
import io.blindnet.blindnet.signal.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.util.KeyHelper;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.*;

public class Main {

    // used for testing purposes during development
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        BlindnetSignal blindnetSignal2 = BlindnetSignalProvider.getInstance(
                "/Users/stefanveselinovic/Desktop/blindnetdb2/",
                "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHAiOiI0MWRmMTBlYS05NjY4LTQwMTItYjRiNS04NTYyM2UyNzc5N2YiLCJ1aWQiOiJ0ZXN0NjA5IiwibmJmIjoxNjI5ODI0MTA3LCJleHAiOjE2Mjk4NjczMDcsImlhdCI6MTYyOTgyNDEwN30.kjr2dsbJKSp84l9j9ZsbR1O1bBymrwALxkZqh70Id0Ew6pLTpr_yqDBQg8mt0S-T1mkPFoRNpildzNkSseuECg");
////
//        UserRegistrationResult result = blindnetSignal2.register();
//        System.out.println("Result is " + result.isSuccessful());
////
//        List<String> ids = new ArrayList<>();
//        ids.add("test611");
//        Map<String, Object> metadata = new HashMap<>();
//        metadata.put("metadatakey1", "metadataobject1");
//        MessageArrayWrapper messageArrayWrapper = new MessageArrayWrapper(metadata, "data321".getBytes());
//        blindnetSignal2.encryptMessage(ids, messageArrayWrapper);
//        System.out.println("ENCRYPTED MESSAGES OLE OLE");

        // blindnetSignal2.decryptMessage("test611", blindnetSignal2.readDeviceId());


//        BlindnetSignal blindnetSignal = BlindnetSignalProvider.getInstance("/Users/stefanveselinovic/Desktop/blindnetkeys/",
//                "/Users/stefanveselinovic/Desktop/blindnetdb/",
//                "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHAiOiI0MWRmMTBlYS05NjY4LTQwMTItYjRiNS04NTYyM2UyNzc5N2YiLCJ1aWQiOiJ0ZXN0NjExIiwibmJmIjoxNjI5ODQyMzg1LCJleHAiOjE2Mjk4ODU1ODUsImlhdCI6MTYyOTg0MjM4NX0.PoMhR_BxldK8mAg-qPDWwIeuKbnL2a5Au7_axTYTmVJflrDVvhQrrhkk83dPBeuxpuUlJJL-UAY3ekz5gGp1Dg");
//
//
//        UserRegistrationResult result2 = blindnetSignal.register();
//        System.out.println("Result is " + result2.isSuccessful());
        // blindnetSignal.decryptMessage("test610", blindnetSignal.readDeviceId(), encrypted);
//
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


// TESTING ENCRYPTION
// =============================================================================================================================
//        SignalKeyStorage signalKeyStorage = new SignalKeyStorage();
//        SessionStore sessionStore = new SignalSessionStore();
//        PreKeyStore preKeyStore = new SignalPreKeyStore(signalKeyStorage);
//        SignedPreKeyStore signedPreKeyStore = new SignalSignedPreKeyStore(signalKeyStorage);
//        IdentityKeyStore identityKeyStore = new SignalIdentityKeyStore(signalKeyStorage);
//
//        String deviceID = "123";
//        String name = "randomanem";
//        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(name, Integer.parseInt(deviceID));
//
//        SessionBuilder sessionBuilder = new SessionBuilder(sessionStore,
//                preKeyStore,
//                signedPreKeyStore,
//                identityKeyStore,
//                signalProtocolAddress);
//
//        IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
//        // generate identity key pair id
//        int registrationId = KeyHelper.generateRegistrationId(false);
//        SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, ThreadLocalRandom.current().nextInt());
//
//        //generate set of ten pre key pairs
//        int startId = ThreadLocalRandom.current().nextInt();
//        List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(startId, 10);
//        PreKeyRecord preKeyRecord = preKeys.get(0);
//
//        PreKeyBundle preKeyBundle = new PreKeyBundle(registrationId,
//                Integer.parseInt(deviceID),
//                preKeyRecord.getId(),
//                preKeyRecord.getKeyPair().getPublicKey(),
//                signedPreKey.getId(),
//                signedPreKey.getKeyPair().getPublicKey(),
//                signedPreKey.getSignature(),
//                identityKeyPair.getPublicKey());
//
//        sessionBuilder.process(preKeyBundle);
//
//        SessionCipher sessionCipher = new SessionCipher(sessionStore,
//                preKeyStore,
//                signedPreKeyStore,
//                identityKeyStore,
//                signalProtocolAddress);
//
//
//        CiphertextMessage message = sessionCipher.encrypt("randomdata".getBytes());
//        System.out.println("encrypted message" + message);
// =============================================================================================================================

//
//        SignalPublicKeysResponse signalPublicKeysResponse = signalApiClient.fetchPublicKeys("stefan-232-test");
//        System.out.println("fetched everything");
    }

    public static void connect() {
        Connection conn = null;
        try {
            // db parameters
            String url = "jdbc:sqlite:/Users/stefanveselinovic/Desktop/sqlite/chinook.db";
            // create a connection to the database
            conn = DriverManager.getConnection(url);

            System.out.println("Connection to SQLite has been established.");

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        } finally {
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException ex) {
                System.out.println(ex.getMessage());
            }
        }
    }

}
