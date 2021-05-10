package io.blindnet.blindnet.core;

import org.junit.AfterClass;
import org.junit.BeforeClass;

import java.io.File;
import java.security.Security;

public class AbstractTest {

    protected static final String TEST_JWT = "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHBfaWQiOiJjNjFmMTliYS04MDBjLTRjNTItOWZiNS0zZWU3NmNvMTg5MjYiLCJuYmYiOjE2MjA2ODk3MTgsImV4cCI6MTYyMTEyMTcxOCwiaWF0IjoxNjIwNjg5NzE4fQ.n9OAGXW_6VvnTkQ_I6_0neeoE4ZV3UROwcjGvnQc5y8H3U20eZGSESbccRjBviIjd58FeUYXV6pSXQWBWXdhDw";
    protected static final String encryptionKeyFilePath = System.getProperty("java.io.tmpdir") + File.separator + "enc.pem";
    protected static final String signingKeyFilePath = System.getProperty("java.io.tmpdir") + File.separator + "sig.pem";
    protected static final String recipientSigningPublicKeyFolderPath = System.getProperty("java.io.tmpdir") + File.separator;


    @BeforeClass
    public static void classSetup() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyStorageConfig.INSTANCE.setup(encryptionKeyFilePath,
                signingKeyFilePath,
                recipientSigningPublicKeyFolderPath);

        JwtConfig.INSTANCE.setup(TEST_JWT);
    }

    @AfterClass
    public static void classCleanup() {
        File encryptionKeyFile = new File(KeyStorageConfig.INSTANCE.getEncryptionPrivateKeyPath());
        encryptionKeyFile.delete();

        File signingKeyFile = new File(KeyStorageConfig.INSTANCE.getSigningPrivateKeyPath());
        signingKeyFile.delete();

        deleteFolder(new File(KeyStorageConfig.INSTANCE.getRecipientSigningPublicKeyFolderPath()));
    }

    private static void deleteFolder(File folder) {
        File[] files = folder.listFiles();
        if (files != null) {
            for (File f : files) {
                if (f.isDirectory()) {
                    deleteFolder(f);
                } else {
                    f.delete();
                }
            }
        }
        folder.delete();
    }

}
