package io.blindnet.blindnet.core;

import io.blindnet.blindnet.internal.JwtConfig;
import io.blindnet.blindnet.internal.KeyStorageConfig;
import org.junit.AfterClass;
import org.junit.BeforeClass;

import java.io.File;
import java.security.Security;

public class AbstractTest {

    protected static final String TEST_JWT = "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHAiOiJjNjFmMTliYS04MDBjLTRjNTItOWZiNS0zZWU3NmNvMTg5MjYiLCJ1aWQiOiJzdGVmYW4tMiIsImdpZCI6ImcxIiwibmJmIjoxNjIxNDM4MTY2LCJleHAiOjE2MjE4NzAxNjYsImlhdCI6MTYyMTQzODE2Nn0.2wakPucRkG1v_fWzRgB-rT3liK0yJT21I9Z4tULDuNGUsYpHPJ4fz6lbqcBQd2b1w3kwCaX8bLhi-8LDT_4aDg";
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
