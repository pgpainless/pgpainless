// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer;

import java.util.Comparator;

import org.bouncycastle.openpgp.PGPSignature;

/**
 * Comparator which can be used to sort signatures with regard to their creation time.
 */
public class SignatureCreationDateComparator implements Comparator<PGPSignature> {

    public static final Order DEFAULT_ORDER = Order.OLD_TO_NEW;

    public enum Order {
        /**
         * Oldest signatures first.
         */
        OLD_TO_NEW,

        /**
         * Newest signatures first.
         */
        NEW_TO_OLD
    }

    private final Order order;

    /**
     * Create a new comparator which sorts signatures old to new.
     */
    public SignatureCreationDateComparator() {
        this(DEFAULT_ORDER);
    }

    /**
     * Create a new comparator which sorts signatures according to the passed ordering.
     * @param order ordering
     */
    public SignatureCreationDateComparator(Order order) {
        this.order = order;
    }

    @Override
    public int compare(PGPSignature one, PGPSignature two) {
        return order == Order.OLD_TO_NEW
                ? one.getCreationTime().compareTo(two.getCreationTime())
                : two.getCreationTime().compareTo(one.getCreationTime());
    }
}
