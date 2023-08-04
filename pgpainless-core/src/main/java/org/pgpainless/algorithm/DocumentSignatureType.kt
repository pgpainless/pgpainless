// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

enum class DocumentSignatureType(val signatureType: SignatureType) {

    /**
     * Signature is calculated over the unchanged binary data.
     */
    BINARY_DOCUMENT(SignatureType.BINARY_DOCUMENT),

    /**
     * The signature is calculated over the text data with its line endings
     * converted to `<CR><LF>`.
     */
    CANONICAL_TEXT_DOCUMENT(SignatureType.CANONICAL_TEXT_DOCUMENT),
    ;
}