package io.blindnet.blindnet.core;

import org.junit.AfterClass;
import org.junit.BeforeClass;

import java.io.File;
import java.security.Security;

public class AbstractTest {

    protected static final String TEST_JWT = "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHBfaWQiOiJjNjFmMTliYS04MDBjLTRjNTItOWZiNS0zZWU3NmNvMTg5MjYiLCJ1c2VyX2lkIjoiMTIzNCIsInVzZXJfaWRzIjoiYWJjIiwidXNlcl9ncm91cF9pZCI6IjU2NzgiLCJuYmYiOjE2MjA3MzU3NTUsImV4cCI6MTYyMTE2Nzc1NSwiaWF0IjoxNjIwNzM1NzU1fQ.fWwg7iaa1ab3DmH6bKEyqjDV9oUHP13v4oz3DX2NFhq1VcDrPIIhQaflBN6E9efAnxcfE7RISZQhjIv-o5t4Dg";
    protected static final String encryptionKeyFilePath = System.getProperty("java.io.tmpdir") + File.separator + "enc.pem";
    protected static final String signingKeyFilePath = System.getProperty("java.io.tmpdir") + File.separator + "sig.pem";
    protected static final String recipientSigningPublicKeyFolderPath = System.getProperty("java.io.tmpdir") + File.separator;

    protected static final String INVALID_NONCE_IV_ALGORITHM = "NceAndIV";
    protected static final String INVALID_SYMMETRIC_ALGORITHM = "ASE";
    protected static final String INVALID_EdDSA_ALGORITHM = "Edd2199";
    protected static final String INVALID_PROVIDER = "CBC";
    protected static final String INVALID_ASYMMETRIC_ALGORITHM = "RAS";
    protected static final String INVALID_PBKDF_SHA256 = "PBKDFFF_SHA256";

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
