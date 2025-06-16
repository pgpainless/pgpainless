// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import kotlin.Unit;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.pgpainless.signature.subpackets.SignatureSubpacketsTest.toArray;

public class SelfSignatureSubpacketsTest {

    @Test
    public void testNopDoesNothing() {
        SignatureSubpackets subpackets = new SignatureSubpackets();
        SelfSignatureSubpackets.Callback cb = SelfSignatureSubpackets.nop();

        cb.modifyHashedSubpackets(subpackets);
        assertEquals(0, toArray(subpackets).length);

        cb.modifyUnhashedSubpackets(subpackets);
        assertEquals(0, toArray(subpackets).length);
    }

    @Test
    public void testApplyHashed() {
        SignatureSubpackets subpackets = new SignatureSubpackets();
        SelfSignatureSubpackets.Callback cb = SelfSignatureSubpackets.applyHashed(
                selfSignatureSubpackets -> {
                    selfSignatureSubpackets.setKeyFlags(KeyFlag.CERTIFY_OTHER);
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
        SelfSignatureSubpackets.Callback cb = SelfSignatureSubpackets.applyUnhashed(
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

        SelfSignatureSubpackets.Callback first = SelfSignatureSubpackets.applyHashed(selfSignatureSubpackets -> {
            selfSignatureSubpackets.setPreferredHashAlgorithms(HashAlgorithm.SHA256, HashAlgorithm.SHA512);
            selfSignatureSubpackets.setKeyFlags(KeyFlag.CERTIFY_OTHER);
            selfSignatureSubpackets.addNotationData(false, "test@pgpainless.org", "foo");
            return Unit.INSTANCE;
        });

        SelfSignatureSubpackets.Callback second = SelfSignatureSubpackets.applyHashed(selfSignatureSubpackets -> {
            selfSignatureSubpackets.setKeyFlags(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA);
            selfSignatureSubpackets.addNotationData(false, "test@pgpainless.org", "bar");
            return Unit.INSTANCE;
        });

        SelfSignatureSubpackets.Callback both = first.then(second);
        both.modifyUnhashedSubpackets(subpackets);
        assertEquals(0, toArray(subpackets).length);

        both.modifyHashedSubpackets(subpackets);

        SignatureSubpacket[] array = toArray(subpackets);
        assertEquals(4, array.length);
        PreferredAlgorithms hashAlgs = (PreferredAlgorithms) array[0];
        assertArrayEquals(
                new int[] {HashAlgorithm.SHA256.getAlgorithmId(), HashAlgorithm.SHA512.getAlgorithmId()},
                hashAlgs.getPreferences());
        NotationData n1 = (NotationData) array[1];
        assertEquals("foo", n1.getNotationValue());
        KeyFlags flags = (KeyFlags) array[2];
        assertEquals(KeyFlag.toBitmask(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA), flags.getFlags());
        NotationData n2 = (NotationData) array[3];
        assertEquals("bar", n2.getNotationValue());
    }
}
