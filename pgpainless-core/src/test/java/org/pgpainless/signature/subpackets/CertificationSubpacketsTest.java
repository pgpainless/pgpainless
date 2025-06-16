// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import kotlin.Unit;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.NotationData;
import org.junit.jupiter.api.Test;
import org.pgpainless.key.TestKeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.pgpainless.signature.subpackets.SignatureSubpacketsTest.toArray;

public class CertificationSubpacketsTest {

    @Test
    public void testNopDoesNothing() {
        SignatureSubpackets subpackets = new SignatureSubpackets();
        CertificationSubpackets.Callback cb = CertificationSubpackets.nop();

        cb.modifyHashedSubpackets(subpackets);
        assertEquals(0, toArray(subpackets).length);

        cb.modifyUnhashedSubpackets(subpackets);
        assertEquals(0, toArray(subpackets).length);
    }

    @Test
    public void testApplyHashed() {
        SignatureSubpackets subpackets = new SignatureSubpackets();
        CertificationSubpackets.Callback cb = CertificationSubpackets.applyHashed(
                selfSignatureSubpackets -> {
                    selfSignatureSubpackets.setIssuerFingerprint(new IssuerFingerprint(false, 4, TestKeys.ROMEO_FINGERPRINT.getBytes()));
                    return Unit.INSTANCE;
                });

        assertEquals(0, toArray(subpackets).length);

        // The callback only applies to hashed subpackets, so modifying unhashed area does nothing
        cb.modifyUnhashedSubpackets(subpackets);
        assertEquals(0, toArray(subpackets).length);

        cb.modifyHashedSubpackets(subpackets);
        assertEquals(1, toArray(subpackets).length);
    }

    @Test
    public void testApplyUnhashed() {
        SignatureSubpackets subpackets = new SignatureSubpackets();
        CertificationSubpackets.Callback cb = CertificationSubpackets.applyUnhashed(
                selfSignatureSubpackets -> {
                    selfSignatureSubpackets.setIssuerKeyId(123L);
                    return Unit.INSTANCE;
                });

        assertEquals(0, toArray(subpackets).length);

        // The callback only applies to unhashed subpackets, so modifying hashed area does nothing
        cb.modifyHashedSubpackets(subpackets);
        assertEquals(0, toArray(subpackets).length);

        cb.modifyUnhashedSubpackets(subpackets);
        assertEquals(1, toArray(subpackets).length);
    }

    @Test
    public void testThen() {
        SignatureSubpackets subpackets = new SignatureSubpackets();

        CertificationSubpackets.Callback first = CertificationSubpackets.applyHashed(selfSignatureSubpackets -> {
            selfSignatureSubpackets.setIssuerFingerprint(new IssuerFingerprint(false, 4, TestKeys.ROMEO_FINGERPRINT.getBytes()));
            selfSignatureSubpackets.addNotationData(false, "test@pgpainless.org", "foo");
            return Unit.INSTANCE;
        });

        CertificationSubpackets.Callback second = CertificationSubpackets.applyHashed(selfSignatureSubpackets -> {
            selfSignatureSubpackets.setIssuerFingerprint(new IssuerFingerprint(true, 4, TestKeys.ROMEO_FINGERPRINT.getBytes()));
            selfSignatureSubpackets.addNotationData(false, "test@pgpainless.org", "bar");
            return Unit.INSTANCE;
        });

        CertificationSubpackets.Callback both = first.then(second);
        both.modifyUnhashedSubpackets(subpackets);
        assertEquals(0, toArray(subpackets).length);

        both.modifyHashedSubpackets(subpackets);

        SignatureSubpacket[] array = toArray(subpackets);
        assertEquals(3, array.length);
        NotationData n1 = (NotationData) array[0];
        assertEquals("foo", n1.getNotationValue());
        IssuerFingerprint fingerprint = (IssuerFingerprint) array[1];
        assertTrue(fingerprint.isCritical());
        NotationData n2 = (NotationData) array[2];
        assertEquals("bar", n2.getNotationValue());
    }
}
