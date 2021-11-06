// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

public interface SignatureSubpacketCallback<S extends BaseSignatureSubpackets> {

    /**
     * Callback method that can be used to modify the hashed subpackets of a signature.
     *
     * @param hashedSubpackets hashed subpackets
     */
    default void modifyHashedSubpackets(S hashedSubpackets) {

    }

    /**
     * Callback method that can be used to modify the unhashed subpackets of a signature.
     *
     * @param unhashedSubpackets unhashed subpackets
     */
    default void modifyUnhashedSubpackets(S unhashedSubpackets) {

    }
}
