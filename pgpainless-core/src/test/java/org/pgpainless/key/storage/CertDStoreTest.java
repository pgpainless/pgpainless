package org.pgpainless.key.storage;

import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertDStoreTest {

    @Test
    public void testGetDefaultBaseDir() {
        CertDStore store = new CertDStore();
        File baseDir = store.getBaseDirectory();
        assertEquals("pgp.cert.d", baseDir.getName());
    }
}
