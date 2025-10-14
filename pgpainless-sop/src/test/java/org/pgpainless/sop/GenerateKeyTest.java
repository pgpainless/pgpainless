// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.Passphrase;
import sop.SOP;
import sop.exception.SOPGPException;

public class GenerateKeyTest {

    private SOP sop;

    @BeforeEach
    public void prepare() {
        sop = new SOPImpl();
    }

    @Test
    public void generateKey() throws IOException {
        PGPainless api = PGPainless.getInstance();
        byte[] bytes = sop.generateKey()
                .userId("Alice <alice@pgpainless.org>")
                .generate()
                .getBytes();

        OpenPGPKey secretKeys = api.readKey().parseKey(bytes);

        for (OpenPGPCertificate.OpenPGPComponentKey subkey : secretKeys.getValidKeys()) {
            PGPPublicKey pubKey = subkey.getPGPPublicKey();
            if (subkey.isPrimaryKey()) {
                continue;
            }
            PGPSignature binding = pubKey.getKeySignatures().next();
            for (KeyIdentifier issuer : binding.getKeyIdentifiers()) {
                assertTrue(issuer.matchesExplicit(secretKeys.getKeyIdentifier()),
                        "Subkey signature MUST be issued by primary key.");
            }
        }

        assertTrue(secretKeys.getUserId("Alice <alice@pgpainless.org>").isBound());
    }

    @Test
    public void generateKeyWithMultipleUserIds() throws IOException {
        PGPainless api = PGPainless.getInstance();
        byte[] bytes = sop.generateKey()
                .userId("Alice <alice@pgpainless.org>")
                .userId("Al <al@example.org>")
                .generate()
                .getBytes();

        OpenPGPKey secretKeys = api.readKey().parseKey(bytes);

        assertEquals("Alice <alice@pgpainless.org>", secretKeys.getPrimaryUserId().getUserId());
        assertTrue(secretKeys.getUserId("Alice <alice@pgpainless.org>").isBound());
        assertTrue(secretKeys.getUserId("Al <al@example.org>").isBound());
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
        PGPainless api = PGPainless.getInstance();
        byte[] bytes = sop.generateKey()
                .userId("Alice")
                .userId("Bob")
                .withKeyPassword("sw0rdf1sh")
                .generate()
                .getBytes();

        OpenPGPKey secretKey = api.readKey().parseKey(bytes);

        assertNotNull(secretKey.getUserId("Alice"));
        assertNotNull(secretKey.getUserId("Bob"));

        for (OpenPGPKey.OpenPGPSecretKey key : secretKey.getSecretKeys().values()) {
            assertNotNull(UnlockSecretKey.unlockSecretKey(key, Passphrase.fromPassword("sw0rdf1sh")));
        }
    }

    @Test
    public void invalidProfile() {
        assertThrows(SOPGPException.UnsupportedProfile.class, () ->
                sop.generateKey().profile("invalid"));
    }

    @Test
    public void generateKeyWithNewlinesInUserId() throws IOException {
        byte[] keyBytes = sop.generateKey()
                .userId("Foo\n\nBar")
                .generate()
                .getBytes();

        OpenPGPKey key = PGPainless.getInstance().readKey().parseKey(keyBytes);
        assertTrue(key.getValidUserIds().get(0).getUserId().equals("Foo\n\nBar"));
    }
}
