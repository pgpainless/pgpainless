// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

public class SignatureSubpacketTest {

    @Test
    public void testFromCodes() {
        int[] codes = new int[] {
                SignatureSubpacket.issuerKeyId.getCode(),
                SignatureSubpacket.preferredSymmetricAlgorithms.getCode(),
                SignatureSubpacket.preferredHashAlgorithms.getCode()
        };

        List<SignatureSubpacket> subpacketList = SignatureSubpacket.fromCodes(codes);
        assertEquals(3, subpacketList.size());
        assertEquals(SignatureSubpacket.issuerKeyId, subpacketList.get(0));
        assertEquals(SignatureSubpacket.preferredSymmetricAlgorithms, subpacketList.get(1));
        assertEquals(SignatureSubpacket.preferredHashAlgorithms, subpacketList.get(2));
    }
}
