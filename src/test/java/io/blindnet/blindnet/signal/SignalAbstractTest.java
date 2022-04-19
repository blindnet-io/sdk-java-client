package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.internal.DatabaseConfig;
import io.blindnet.blindnet.internal.TokenConfig;
import org.junit.AfterClass;
import org.junit.BeforeClass;

import java.io.File;
import java.security.Security;
import java.util.Base64;

public abstract class SignalAbstractTest {

    protected static final String TEST_TOKEN = "eyJhbGciOiJFZERTQSIsInR5cCI6Imp3dCJ9.eyJhcHAiOiJjNjFmMTliYS04MDBjLTRjNTItOWZiNS0zZWU3NmNvMTg5MjYiLCJ1aWQiOiJzdGVmYW4tMiIsImdpZCI6ImcxIiwibmJmIjoxNjIxNDM4MTY2LCJleHAiOjE2MjE4NzAxNjYsImlhdCI6MTYyMTQzODE2Nn0.2wakPucRkG1v_fWzRgB-rT3liK0yJT21I9Z4tULDuNGUsYpHPJ4fz6lbqcBQd2b1w3kwCaX8bLhi-8LDT_4aDg";
    protected static final String DEVICE_ONE_ID = "1";
    protected static final String USER_ONE_ID = "user_one_id";
    protected static final String SIGNAL_ADDRESS_ONE_NAME = "signal_address_name";
    protected static final String DEVICE_TWO_ID = "2";
    protected static final String USER_TWO_ID = "user_two_id";

    protected Base64.Encoder encoder = Base64.getEncoder();

    @BeforeClass
    public static void classSetup() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        DatabaseConfig.INSTANCE.setup(System.getProperty("java.io.tmpdir"));
        TokenConfig.INSTANCE.setup(TEST_TOKEN);
    }

    @AfterClass
    public static void classCleanup() {
        deleteFolder(new File(DatabaseConfig.INSTANCE.getDbPath()));
    }

    protected static void deleteFolder(File folder) {
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
