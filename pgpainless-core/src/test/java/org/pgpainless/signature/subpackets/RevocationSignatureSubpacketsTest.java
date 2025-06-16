// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import kotlin.Unit;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.junit.jupiter.api.Test;
import org.pgpainless.key.util.RevocationAttributes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.pgpainless.signature.subpackets.SignatureSubpacketsTest.toArray;

public class RevocationSignatureSubpacketsTest {

    @Test
    public void testNopDoesNothing() {
        SignatureSubpackets subpackets = new SignatureSubpackets();
        RevocationSignatureSubpackets.Callback cb = RevocationSignatureSubpackets.nop();

        cb.modifyHashedSubpackets(subpackets);
        assertEquals(0, toArray(subpackets).length);

        cb.modifyUnhashedSubpackets(subpackets);
        assertEquals(0, toArray(subpackets).length);
    }


    @Test
    public void testApplyHashed() {
        SignatureSubpackets subpackets = new SignatureSubpackets();
        RevocationSignatureSubpackets.Callback cb = RevocationSignatureSubpackets.applyHashed(
                selfSignatureSubpackets -> {
                    selfSignatureSubpackets.setRevocationReason(true, RevocationAttributes.Reason.KEY_COMPROMISED, "Leaked");
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
        RevocationSignatureSubpackets.Callback cb = RevocationSignatureSubpackets.applyUnhashed(
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

        RevocationSignatureSubpackets.Callback first = RevocationSignatureSubpackets.applyHashed(selfSignatureSubpackets -> {
            selfSignatureSubpackets.setRevocationReason(true, RevocationAttributes.Reason.KEY_COMPROMISED, "Leakett (typo)");
            selfSignatureSubpackets.addNotationData(false, "test@pgpainless.org", "foo");
            return Unit.INSTANCE;
        });

        RevocationSignatureSubpackets.Callback second = RevocationSignatureSubpackets.applyHashed(selfSignatureSubpackets -> {
            selfSignatureSubpackets.setRevocationReason(true, RevocationAttributes.Reason.KEY_COMPROMISED, "Leaked");
            selfSignatureSubpackets.addNotationData(false, "test@pgpainless.org", "bar");
            return Unit.INSTANCE;
        });

        RevocationSignatureSubpackets.Callback both = first.then(second);
        both.modifyUnhashedSubpackets(subpackets);
        assertEquals(0, toArray(subpackets).length);

        both.modifyHashedSubpackets(subpackets);

        SignatureSubpacket[] array = toArray(subpackets);
        assertEquals(3, array.length);
        NotationData n1 = (NotationData) array[0];
        assertEquals("foo", n1.getNotationValue());
        RevocationReason reason = (RevocationReason) array[1];
        assertEquals(RevocationAttributes.Reason.KEY_COMPROMISED.code(), reason.getRevocationReason());
        NotationData n2 = (NotationData) array[2];
        assertEquals("bar", n2.getNotationValue());
    }
}
