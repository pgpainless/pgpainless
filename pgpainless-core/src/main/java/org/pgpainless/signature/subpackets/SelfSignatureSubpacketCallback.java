// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

public interface SelfSignatureSubpacketCallback {

    void modifyHashedSubpackets(SelfSignatureSubpackets subpackets);

    void modifyUnhashedSubpackets(SelfSignatureSubpackets subpackets);

}
