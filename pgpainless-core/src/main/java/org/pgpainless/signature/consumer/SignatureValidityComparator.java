// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer;

import java.util.Comparator;

import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.signature.SignatureUtils;

/**
 * Comparator which sorts signatures based on an ordering and on revocation hardness.
 *
 * If a list of signatures gets ordered using this comparator, hard revocations will always
 * come first.
 * Further, signatures are ordered by date according to the {@link SignatureCreationDateComparator.Order}.
 */
public class SignatureValidityComparator implements Comparator<PGPSignature> {

    private final SignatureCreationDateComparator creationDateComparator;

    /**
     * Create a new {@link SignatureValidityComparator} which orders signatures the oldest first.
     * Still, hard revocations will come first.
     */
    public SignatureValidityComparator() {
        this(SignatureCreationDateComparator.DEFAULT_ORDER);
    }

    /**
     * Create a new {@link SignatureValidityComparator} which orders signatures following the passed ordering.
     * Still, hard revocations will come first.
     */
    public SignatureValidityComparator(SignatureCreationDateComparator.Order order) {
        this.creationDateComparator = new SignatureCreationDateComparator(order);
    }

    @Override
    public int compare(PGPSignature one, PGPSignature two) {
        boolean oneIsHard = SignatureUtils.isHardRevocation(one);
        boolean twoIsHard = SignatureUtils.isHardRevocation(two);

        // both have same "hardness", so compare creation time
        if (oneIsHard == twoIsHard) {
            return creationDateComparator.compare(one, two);
        }
        // favor the "harder" signature
        return oneIsHard ? -1 : 1;
    }
}
