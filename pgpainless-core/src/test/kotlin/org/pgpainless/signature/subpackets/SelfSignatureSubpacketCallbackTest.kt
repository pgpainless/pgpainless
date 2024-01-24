// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets

import java.util.*
import openpgp.toSecondsPrecision
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.pgpainless.algorithm.Feature
import org.pgpainless.algorithm.KeyFlag

class SelfSignatureSubpacketCallbackTest {

    @Test
    fun testSetHashedSignatureCreationTimeViaCallback() {
        val subpackets: SelfSignatureSubpackets = SignatureSubpackets.createEmptySubpackets()
        val date = Date().toSecondsPrecision()
        val callback = SelfSignatureSubpackets.applyHashed { setSignatureCreationTime(date) }

        callback.modifyHashedSubpackets(subpackets)

        assertEquals(subpackets.getSignatureCreationTime(), date)
    }

    @Test
    fun testSetUnhashedSignatureCreationTimeViaCallback() {
        val subpackets: SelfSignatureSubpackets = SignatureSubpackets.createEmptySubpackets()
        val date = Date().toSecondsPrecision()
        val callback = SelfSignatureSubpackets.applyUnhashed { setSignatureCreationTime(date) }

        callback.modifyUnhashedSubpackets(subpackets)

        assertEquals(subpackets.getSignatureCreationTime(), date)
    }

    @Test
    fun `test that mismatching applyHashed() with modifyUnhashedSubpackets() will not modify the subpackets`() {
        val subpackets: SelfSignatureSubpackets = SignatureSubpackets.createEmptySubpackets()
        val callback =
            SelfSignatureSubpackets.applyHashed {
                setKeyFlags(KeyFlag.CERTIFY_OTHER)
                setFeatures(Feature.MODIFICATION_DETECTION)
            }

        callback.modifyUnhashedSubpackets(subpackets)

        assertNull(subpackets.getKeyFlagsPacket())
        assertNull(subpackets.getFeaturesPacket())
    }

    @Test
    fun testThen() {
        val subpackets: SelfSignatureSubpackets = SignatureSubpackets.createEmptySubpackets()
        val firstCallback =
            SelfSignatureSubpackets.applyHashed {
                addNotationData(false, "test@pgpainless.org", "foo-bar")
                setFeatures(Feature.MODIFICATION_DETECTION)
            }
        val secondCallback =
            SelfSignatureSubpackets.applyHashed {
                clearNotationData()
                setKeyFlags(KeyFlag.CERTIFY_OTHER)
            }

        // removes the notation, but preserves the features and adds key-flags
        firstCallback.then(secondCallback).modifyHashedSubpackets(subpackets)

        assertTrue(subpackets.getNotationDataPackets().isEmpty())
        assertEquals(listOf(Feature.MODIFICATION_DETECTION), subpackets.getFeatures())
        assertEquals(listOf(KeyFlag.CERTIFY_OTHER), subpackets.getKeyFlags())
    }
}
