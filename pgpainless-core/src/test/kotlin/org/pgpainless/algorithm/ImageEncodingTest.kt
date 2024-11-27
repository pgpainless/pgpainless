// SPDX-FileCopyrightText: 2024 Paul Schaub <info@pgpainless.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class ImageEncodingTest {

    @Test
    fun parseJpeg() {
        assertEquals(ImageEncoding.JPEG, ImageEncoding.requireFromId(1))
    }

    @Test
    fun parseUnknown() {
        assertNull(ImageEncoding.fromId(11))
        assertThrows<NoSuchElementException> { ImageEncoding.requireFromId(11) }
    }
}
