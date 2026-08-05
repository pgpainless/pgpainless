// SPDX-FileCopyrightText: 2024 Paul Schaub <info@pgpainless.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

/**
 * Image encoding schemes for user attribute image headers.
 * Currently, only [JPEG] is defined.
 */
enum class ImageEncoding(val id: Int) {

    /** JPEG File Interchange Format (JFIF). */
    JPEG(1)
    ;

    companion object {
        @JvmStatic
        fun requireFromId(id: Int): ImageEncoding =
            fromId(id) ?: throw NoSuchElementException("No ImageEncoding found for id $id")

        @JvmStatic
        fun fromId(id: Int): ImageEncoding? = values().firstOrNull { id == it.id }
    }
}
