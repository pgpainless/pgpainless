/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.signature;

import java.util.Comparator;

import org.bouncycastle.openpgp.PGPSignature;

/**
 * Comparator which sorts signatures based on an ordering and on revocation hardness.
 *
 * If a list of signatures gets ordered using this comparator, hard revocations will always
 * come first.
 * Further, signatures are ordered by date according to the {@link org.pgpainless.signature.SignatureCreationDateComparator.Order}.
 */
public class SignatureValidityComparator implements Comparator<PGPSignature> {

    private final SignatureCreationDateComparator.Order order;
    private final SignatureCreationDateComparator creationDateComparator;

    /**
     * Create a new {@link SignatureValidityComparator} which orders signatures oldest first.
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
        this.order = order;
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
