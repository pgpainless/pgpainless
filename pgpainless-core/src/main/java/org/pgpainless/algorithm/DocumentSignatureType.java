// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

/**
 * Subset of {@link SignatureType}, used for signatures over documents.
 */
public enum DocumentSignatureType {

    /**
     * Signature is calculated over the unchanged binary data.
     */
    BINARY_DOCUMENT(SignatureType.BINARY_DOCUMENT),

    /**
     * The signature is calculated over the text data with its line endings converted to
     * <pre>
     *     {@code &lt;CR&gt;&lt;LF&gt;}
     * </pre>.
     */
    CANONICAL_TEXT_DOCUMENT(SignatureType.CANONICAL_TEXT_DOCUMENT),
    ;

    final SignatureType signatureType;

    DocumentSignatureType(SignatureType signatureType) {
        this.signatureType = signatureType;
    }

    public SignatureType getSignatureType() {
        return signatureType;
    }
}
