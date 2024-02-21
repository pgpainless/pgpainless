// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer

import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.bouncycastle.extensions.isHardRevocation

/**
 * Comparator which sorts signatures based on an ordering and on revocation hardness.
 *
 * If a list of signatures gets ordered using this comparator, hard revocations will always come
 * first. Further, signatures are ordered by date according to the
 * [SignatureCreationDateComparator.Order].
 */
class SignatureValidityComparator(
    order: SignatureCreationDateComparator.Order = SignatureCreationDateComparator.Order.OLD_TO_NEW
) : Comparator<PGPSignature> {

    private val creationDateComparator: SignatureCreationDateComparator =
        SignatureCreationDateComparator(order)

    override fun compare(one: PGPSignature, two: PGPSignature): Int {
        return if (one.isHardRevocation == two.isHardRevocation) {
            // Both have the same hardness, so compare creation time
            creationDateComparator.compare(one, two)
        }
        // else favor the "harder" signature
        else if (one.isHardRevocation) -1 else 1
    }
}
