// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.junit.JUtils;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

public class AddSubkeyWithModifiedBindingSignatureSubpacketsTest {

    public static final long MILLIS_IN_SEC = 1000;

    @Test
    public void bindEncryptionSubkeyAndModifyBindingSignatureHashedSubpackets() {
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice <alice@pgpainless.org>")
                .getPGPSecretKeyRing();
        KeyRingInfo before = PGPainless.inspectKeyRing(secretKeys);
        List<OpenPGPCertificate.OpenPGPComponentKey> signingKeysBefore = before.getSigningSubkeys();

        PGPKeyPair secretSubkey = KeyRingBuilder.generateKeyPair(
                KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.SIGN_DATA).build(),
                OpenPGPKeyVersion.v4);

        long secondsUntilExpiration = 1000;
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addSubKey(secretSubkey, new SelfSignatureSubpackets.Callback() {
                            @Override
                            public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                                hashedSubpackets.setKeyExpirationTime(true, secondsUntilExpiration);
                                hashedSubpackets.addNotationData(false, "test@test.test", "test");
                            }
                        }, SecretKeyRingProtector.unprotectedKeys(), protector, KeyFlag.SIGN_DATA)
                .done();

        KeyRingInfo after = PGPainless.inspectKeyRing(secretKeys);
        List<OpenPGPCertificate.OpenPGPComponentKey> signingKeysAfter = after.getSigningSubkeys();
        signingKeysAfter.removeAll(signingKeysBefore);
        assertFalse(signingKeysAfter.isEmpty());

        OpenPGPCertificate.OpenPGPComponentKey newKey = signingKeysAfter.get(0);
        Date newExpirationDate = after.getSubkeyExpirationDate(new OpenPgpV4Fingerprint(newKey.getPGPPublicKey()));
        assertNotNull(newExpirationDate);
        Date now = new Date();
        JUtils.assertEquals(
                now.getTime() + MILLIS_IN_SEC * secondsUntilExpiration,
                newExpirationDate.getTime(), 2 * MILLIS_IN_SEC);
        assertTrue(newKey.getPGPPublicKey().getSignatures().hasNext());
        PGPSignature binding = newKey.getPGPPublicKey().getSignatures().next();
        List<NotationData> notations = SignatureSubpacketsUtil.getHashedNotationData(binding);
        assertEquals(1, notations.size());
        assertEquals("test@test.test", notations.get(0).getNotationName());
    }
}
