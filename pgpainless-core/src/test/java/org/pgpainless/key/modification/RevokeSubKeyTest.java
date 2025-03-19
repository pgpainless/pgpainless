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
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
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
import org.pgpainless.signature.subpackets.RevocationSignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.pgpainless.util.TestAllImplementations;
import org.pgpainless.util.Passphrase;

public class RevokeSubKeyTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void revokeSubkeyTest() throws IOException, PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = TestKeys.getCryptieKey();

        Iterator<PGPSecretKey> keysIterator = secretKeys.getPGPSecretKeyRing().iterator();
        PGPSecretKey primaryKey = keysIterator.next();
        PGPSecretKey subKey = keysIterator.next();

        assertFalse(subKey.getPublicKey().hasRevocation());

        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector
                .forKey(secretKeys, Passphrase.fromPassword("password123"));

        secretKeys = api.modify(secretKeys)
                .revokeSubKey(new OpenPgpV4Fingerprint(subKey), protector)
                .done();
        keysIterator = secretKeys.getPGPSecretKeyRing().iterator();
        primaryKey = keysIterator.next();
        subKey = keysIterator.next();

        assertTrue(subKey.getPublicKey().hasRevocation());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void detachedRevokeSubkeyTest() throws IOException, PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = TestKeys.getCryptieKey();
        OpenPgpV4Fingerprint fingerprint = new OpenPgpV4Fingerprint(secretKeys);
        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector.forKey(secretKeys, Passphrase.fromPassword("password123"));

        OpenPGPSignature revocationCertificate = api.modify(secretKeys)
                .createRevocation(fingerprint, protector, RevocationAttributes.createKeyRevocation()
                        .withReason(RevocationAttributes.Reason.KEY_RETIRED)
                        .withDescription("Key no longer used."));

        PGPPublicKey publicKey = secretKeys.getPGPSecretKeyRing().getPublicKey();
        assertFalse(publicKey.hasRevocation());

        publicKey = PGPPublicKey.addCertification(publicKey, revocationCertificate.getSignature());

        assertTrue(publicKey.hasRevocation());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testRevocationSignatureTypeCorrect() throws IOException, PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = TestKeys.getCryptieKey();
        Iterator<PGPPublicKey> keysIterator = secretKeys.getPGPKeyRing().getPublicKeys();
        PGPPublicKey primaryKey = keysIterator.next();
        PGPPublicKey subKey = keysIterator.next();
        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector
                .forKey(secretKeys, Passphrase.fromPassword("password123"));

        SecretKeyRingEditorInterface editor = api.modify(secretKeys);
        OpenPGPSignature keyRevocation = editor.createRevocation(primaryKey.getKeyIdentifier(), protector, (RevocationAttributes) null);
        OpenPGPSignature subkeyRevocation = editor.createRevocation(subKey.getKeyIdentifier(), protector, (RevocationAttributes) null);

        assertEquals(SignatureType.KEY_REVOCATION.getCode(), keyRevocation.getSignature().getSignatureType());
        assertEquals(SignatureType.SUBKEY_REVOCATION.getCode(), subkeyRevocation.getSignature().getSignatureType());
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
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey().modernKeyRing("Alice");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        PGPPublicKey encryptionSubkey = api.inspect(secretKeys)
                .getEncryptionSubkeys(EncryptionPurpose.ANY).get(0).getPGPPublicKey();

        secretKeys = api.modify(secretKeys)
                .revokeSubKey(encryptionSubkey.getKeyIdentifier(), protector)
                .done();

        encryptionSubkey = secretKeys.getPGPSecretKeyRing().getPublicKey(encryptionSubkey.getKeyIdentifier());
        PGPSignature revocation = encryptionSubkey.getSignaturesOfType(SignatureType.SUBKEY_REVOCATION.getCode()).next();
        assertNotNull(revocation);

        assertArrayEquals(
                secretKeys.getPGPSecretKeyRing().getPublicKey().getFingerprint(),
                revocation.getHashedSubPackets().getIssuerFingerprint().getFingerprint());
        assertEquals(secretKeys.getPGPSecretKeyRing().getPublicKey().getKeyID(),
                revocation.getHashedSubPackets().getIssuerKeyID());
        assertNull(SignatureSubpacketsUtil.getRevocationReason(revocation));
        assertTrue(revocation.isHardRevocation());
    }

    @Test
    public void inspectSubpacketsOnModifiedRevocationSignature() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey().modernKeyRing("Alice");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        PGPPublicKey encryptionSubkey = api.inspect(secretKeys)
                .getEncryptionSubkeys(EncryptionPurpose.ANY).get(0).getPGPPublicKey();

        secretKeys = api.modify(secretKeys)
                .revokeSubKey(encryptionSubkey.getKeyIdentifier(), protector, new RevocationSignatureSubpackets.Callback() {
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

        encryptionSubkey = secretKeys.getPGPSecretKeyRing().getPublicKey(encryptionSubkey.getKeyIdentifier());
        PGPSignature revocation = encryptionSubkey.getSignaturesOfType(SignatureType.SUBKEY_REVOCATION.getCode()).next();
        assertNotNull(revocation);

        assertNull(revocation.getHashedSubPackets().getIssuerFingerprint());
        assertEquals(secretKeys.getKeyIdentifier().getKeyId(),
                revocation.getHashedSubPackets().getIssuerKeyID());
        assertNotNull(SignatureSubpacketsUtil.getRevocationReason(revocation));
        assertFalse(revocation.isHardRevocation());
    }
}
