// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.Passphrase;
import sop.SOP;

public class GenerateKeyTest {

    private SOP sop;

    @BeforeEach
    public void prepare() {
        sop = new SOPImpl();
    }

    @Test
    public void generateKey() throws IOException {
        byte[] bytes = sop.generateKey()
                .userId("Alice <alice@pgpainless.org>")
                .generate()
                .getBytes();

        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing()
                .secretKeyRing(bytes);

        assertTrue(PGPainless.inspectKeyRing(secretKeys)
                .isUserIdValid("Alice <alice@pgpainless.org>"));
    }

    @Test
    public void generateKeyWithMultipleUserIds() throws IOException {
        byte[] bytes = sop.generateKey()
                .userId("Alice <alice@pgpainless.org>")
                .userId("Al <al@example.org>")
                .generate()
                .getBytes();

        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing()
                .secretKeyRing(bytes);

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertEquals("Alice <alice@pgpainless.org>", info.getPrimaryUserId());
        assertTrue(info.isUserIdValid("Alice <alice@pgpainless.org>"));
        assertTrue(info.isUserIdValid("Al <al@example.org>"));
    }

    @Test
    public void unarmoredKey() throws IOException {
        byte[] bytes = sop.generateKey()
                .userId("Alice <alice@pgpainless.org>")
                .noArmor()
                .generate()
                .getBytes();

        assertFalse(new String(bytes).startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
    }

    @Test
    public void protectedMultiUserIdKey() throws IOException, PGPException {
        byte[] bytes = sop.generateKey()
                .userId("Alice")
                .userId("Bob")
                .withKeyPassword("sw0rdf1sh")
                .generate()
                .getBytes();

        PGPSecretKeyRing secretKey = PGPainless.readKeyRing().secretKeyRing(bytes);
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);

        assertTrue(info.getUserIds().contains("Alice"));
        assertTrue(info.getUserIds().contains("Bob"));

        for (PGPSecretKey key : secretKey) {
            assertNotNull(UnlockSecretKey.unlockSecretKey(key, Passphrase.fromPassword("sw0rdf1sh")));
        }
    }
}
