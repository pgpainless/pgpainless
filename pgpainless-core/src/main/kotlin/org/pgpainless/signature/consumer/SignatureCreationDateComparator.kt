// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer

import org.bouncycastle.openpgp.PGPSignature

/**
 * Create a new comparator which sorts signatures according to the passed ordering.
 * @param order ordering
 */
class SignatureCreationDateComparator(
        private val order: Order = Order.OLD_TO_NEW
) : Comparator<PGPSignature> {

    enum class Order {
        /**
         * Oldest signatures first.
         */
        OLD_TO_NEW,
        /**
         * Newest signatures first.
         */
        NEW_TO_OLD
    }

    override fun compare(one: PGPSignature, two: PGPSignature): Int {
        return when(order) {
            Order.OLD_TO_NEW -> one.creationTime.compareTo(two.creationTime)
            Order.NEW_TO_OLD -> two.creationTime.compareTo(one.creationTime)
        }
    }
}