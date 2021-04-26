package io.blindnet.blindnet.core;

import org.junit.AfterClass;
import org.junit.BeforeClass;

import java.io.File;
import java.security.Security;

public class AbstractTest {

    protected static final String TEST_JWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
            "eyJhcHAiOiIxMjM0NTY3ODkwIiwidWlkIjoiSm9obiBEb2UiLCJleHAiOjE2MTkyMTgxMzF9." +
            "I1cCDW-hkYgyZABgfYmN_DOI2uCueWMDF5f4nLBdMPtOEzzmyRqALxZ8vhlRlFdOQ9g0vULKe2gvJnj0XyT8jQ";
    protected static final String encryptionKeyFilePath = System.getProperty("java.io.tmpdir") + File.separator + "enc.pem";
    protected static final String signingKeyFilePath = System.getProperty("java.io.tmpdir") + File.separator + "sig.pem";

    @BeforeClass
    public static void classSetup() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyStorageConfig.INSTANCE.setup(encryptionKeyFilePath, signingKeyFilePath);
    }

    @AfterClass
    public static void classCleanup() {
        File encryptionKeyFile = new File(KeyStorageConfig.INSTANCE.getEncryptionPrivateKeyPath());
        encryptionKeyFile.delete();

        File signingKeyFile = new File(KeyStorageConfig.INSTANCE.getSigningPrivateKeyPath());
        signingKeyFile.delete();
    }

}
