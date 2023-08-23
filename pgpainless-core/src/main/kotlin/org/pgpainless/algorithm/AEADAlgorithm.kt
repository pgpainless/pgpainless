// SPDX-FileCopyrightText: 2023 Paul Schaub <info@pgpainless.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

enum class AEADAlgorithm(
        val algorithmId: Int,
        val ivLength: Int,
        val tagLength: Int) {
    EAX(1, 16, 16),
    OCB(2, 15, 16),
    GCM(3, 12, 16),
    ;

    companion object {
        @JvmStatic
        fun fromId(id: Int): AEADAlgorithm? {
            return values().firstOrNull {
                algorithm -> algorithm.algorithmId == id
            }
        }

        @JvmStatic
        fun requireFromId(id: Int): AEADAlgorithm {
            return fromId(id) ?:
            throw NoSuchElementException("No AEADAlgorithm found for id $id")
        }
    }
}