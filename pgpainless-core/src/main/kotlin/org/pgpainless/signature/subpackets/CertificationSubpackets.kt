// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets

interface CertificationSubpackets : BaseSignatureSubpackets {

    interface Callback : SignatureSubpacketCallback<CertificationSubpackets>
}
