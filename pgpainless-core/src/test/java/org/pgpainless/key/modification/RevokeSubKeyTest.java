// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Iterator;

import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.subpackets.RevocationSignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.pgpainless.util.TestAllImplementations;
import org.pgpainless.util.Passphrase;

public class RevokeSubKeyTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void revokeSukeyTest() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();

        Iterator<PGPSecretKey> keysIterator = secretKeys.iterator();
        PGPSecretKey primaryKey = keysIterator.next();
        PGPSecretKey subKey = keysIterator.next();

        assertFalse(subKey.getPublicKey().hasRevocation());

        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector
                .forKey(secretKeys, Passphrase.fromPassword("password123"));

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .revokeSubKey(new OpenPgpV4Fingerprint(subKey), protector)
                .done();
        keysIterator = secretKeys.iterator();
        primaryKey = keysIterator.next();
        subKey = keysIterator.next();

        assertTrue(subKey.getPublicKey().hasRevocation());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void detachedRevokeSubkeyTest() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        OpenPgpV4Fingerprint fingerprint = new OpenPgpV4Fingerprint(secretKeys);
        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector.forKey(secretKeys, Passphrase.fromPassword("password123"));

        PGPSignature revocationCertificate = PGPainless.modifyKeyRing(secretKeys)
                .createRevocation(fingerprint, protector, RevocationAttributes.createKeyRevocation()
                        .withReason(RevocationAttributes.Reason.KEY_RETIRED)
                        .withDescription("Key no longer used."));

        PGPPublicKey publicKey = secretKeys.getPublicKey();
        assertFalse(publicKey.hasRevocation());

        publicKey = PGPPublicKey.addCertification(publicKey, revocationCertificate);

        assertTrue(publicKey.hasRevocation());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testRevocationSignatureTypeCorrect() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        Iterator<PGPPublicKey> keysIterator = secretKeys.getPublicKeys();
        PGPPublicKey primaryKey = keysIterator.next();
        PGPPublicKey subKey = keysIterator.next();
        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector
                .forKey(secretKeys, Passphrase.fromPassword("password123"));

        SecretKeyRingEditorInterface editor = PGPainless.modifyKeyRing(secretKeys);
        PGPSignature keyRevocation = editor.createRevocation(primaryKey.getKeyID(), protector, (RevocationAttributes) null);
        PGPSignature subkeyRevocation = editor.createRevocation(subKey.getKeyID(), protector, (RevocationAttributes) null);

        assertEquals(SignatureType.KEY_REVOCATION.getCode(), keyRevocation.getSignatureType());
        assertEquals(SignatureType.SUBKEY_REVOCATION.getCode(), subkeyRevocation.getSignatureType());
    }

    @Test
    public void testThrowsIfRevocationReasonTypeMismatch() {
        // Key revocation cannot have reason type USER_ID_NO_LONGER_VALID
        assertThrows(IllegalArgumentException.class, () -> RevocationAttributes.createKeyRevocation()
                .withReason(RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID));
        // Cert revocations cannot have the reason types KEY_SUPERSEDED, KEY_COMPROMIZED, KEY_RETIRED
        assertThrows(IllegalArgumentException.class, () -> RevocationAttributes.createCertificateRevocation()
                .withReason(RevocationAttributes.Reason.KEY_SUPERSEDED));
        assertThrows(IllegalArgumentException.class, () -> RevocationAttributes.createCertificateRevocation()
                .withReason(RevocationAttributes.Reason.KEY_COMPROMISED));
        assertThrows(IllegalArgumentException.class, () -> RevocationAttributes.createCertificateRevocation()
                .withReason(RevocationAttributes.Reason.KEY_RETIRED));
    }

    @Test
    public void testReasonToString() {
        RevocationAttributes.Reason reason = RevocationAttributes.Reason.KEY_COMPROMISED;
        assertEquals("2 - KEY_COMPROMISED", reason.toString());
    }

    @Test
    public void inspectSubpacketsOnDefaultRevocationSignature()
            throws PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("Alice")
                .getPGPSecretKeyRing();
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        PGPPublicKey encryptionSubkey = PGPainless.inspectKeyRing(secretKeys)
                .getEncryptionSubkeys(EncryptionPurpose.ANY).get(0).getPGPPublicKey();

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .revokeSubKey(encryptionSubkey.getKeyID(), protector)
                .done();

        encryptionSubkey = secretKeys.getPublicKey(encryptionSubkey.getKeyID());
        PGPSignature revocation = encryptionSubkey.getSignaturesOfType(SignatureType.SUBKEY_REVOCATION.getCode()).next();
        assertNotNull(revocation);

        assertArrayEquals(
                secretKeys.getPublicKey().getFingerprint(),
                revocation.getHashedSubPackets().getIssuerFingerprint().getFingerprint());
        assertEquals(secretKeys.getPublicKey().getKeyID(),
                revocation.getHashedSubPackets().getIssuerKeyID());
        assertNull(SignatureSubpacketsUtil.getRevocationReason(revocation));
        assertTrue(SignatureUtils.isHardRevocation(revocation));
    }

    @Test
    public void inspectSubpacketsOnModifiedRevocationSignature() {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("Alice")
                .getPGPSecretKeyRing();
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        PGPPublicKey encryptionSubkey = PGPainless.inspectKeyRing(secretKeys)
                .getEncryptionSubkeys(EncryptionPurpose.ANY).get(0).getPGPPublicKey();

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .revokeSubKey(encryptionSubkey.getKeyID(), protector, new RevocationSignatureSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(RevocationSignatureSubpackets hashedSubpackets) {
                        hashedSubpackets.setRevocationReason(
                                RevocationAttributes.createKeyRevocation()
                                        .withReason(RevocationAttributes.Reason.KEY_RETIRED)
                                        .withDescription("I have a new Key."));
                        // override issuer-fingerprint with null to test nulling of subpackets
                        hashedSubpackets.setIssuerFingerprint((IssuerFingerprint) null);
                    }
                })
                .done();

        encryptionSubkey = secretKeys.getPublicKey(encryptionSubkey.getKeyID());
        PGPSignature revocation = encryptionSubkey.getSignaturesOfType(SignatureType.SUBKEY_REVOCATION.getCode()).next();
        assertNotNull(revocation);

        assertNull(revocation.getHashedSubPackets().getIssuerFingerprint());
        assertEquals(secretKeys.getPublicKey().getKeyID(),
                revocation.getHashedSubPackets().getIssuerKeyID());
        assertNotNull(SignatureSubpacketsUtil.getRevocationReason(revocation));
        assertFalse(SignatureUtils.isHardRevocation(revocation));
    }
}
