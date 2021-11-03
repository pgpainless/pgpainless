// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

public interface CertificationSubpackets extends BaseSignatureSubpackets {

    interface Callback {
        default void modifyHashedSubpackets(CertificationSubpackets subpackets) {

        }

        default void modifyUnhashedSubpackets(CertificationSubpackets subpackets) {

        }
    }
}
