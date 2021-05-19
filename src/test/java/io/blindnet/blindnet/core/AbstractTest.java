package io.blindnet.blindnet.core;

import org.junit.AfterClass;
import org.junit.BeforeClass;

import java.io.File;
import java.security.Security;

import static io.blindnet.blindnet.core.EncryptionConstants.ENCRYPTION_PRIVATE_KEY_FILENAME;
import static io.blindnet.blindnet.core.EncryptionConstants.SIGNING_PRIVATE_KEY_FILENAME;

public class AbstractTest {

    protected static final String TEST_JWT = "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHBfaWQiOiJjNjFmMTliYS04MDBjLTRjNTItOWZiNS0zZWU3NmNvMTg5MjYiLCJ1c2VyX2lkIjoiMTIzNCIsInVzZXJfaWRzIjoiYWJjIiwidXNlcl9ncm91cF9pZCI6IjU2NzgiLCJuYmYiOjE2MjA3MzU3NTUsImV4cCI6MTYyMTE2Nzc1NSwiaWF0IjoxNjIwNzM1NzU1fQ.fWwg7iaa1ab3DmH6bKEyqjDV9oUHP13v4oz3DX2NFhq1VcDrPIIhQaflBN6E9efAnxcfE7RISZQhjIv-o5t4Dg";
    protected static final String keyFolderPath = System.getProperty("java.io.tmpdir");

    protected static final String INVALID_NONCE_IV_ALGORITHM = "NceAndIV";
    protected static final String INVALID_SYMMETRIC_ALGORITHM = "ASE";
    protected static final String INVALID_EdDSA_ALGORITHM = "Edd2199";
    protected static final String INVALID_PROVIDER = "CBC";
    protected static final String INVALID_ASYMMETRIC_ALGORITHM = "RAS";
    protected static final String INVALID_PBKDF_SHA256 = "PBKDFFF_SHA256";

    @BeforeClass
    public static void classSetup() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyStorageConfig.INSTANCE.setup(keyFolderPath);
        JwtConfig.INSTANCE.setup(TEST_JWT);
    }

    @AfterClass
    public static void classCleanup() {
        File encryptionKeyFile = new File(
                KeyStorageConfig.INSTANCE.getKeyFolderPath() + File.separator + ENCRYPTION_PRIVATE_KEY_FILENAME);
        encryptionKeyFile.delete();

        File signingKeyFile = new File(
                KeyStorageConfig.INSTANCE.getKeyFolderPath() + File.separator + SIGNING_PRIVATE_KEY_FILENAME);
        signingKeyFile.delete();

        deleteFolder(new File(KeyStorageConfig.INSTANCE.getKeyFolderPath()));
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
