// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

enum class EncryptionPurpose {
    /**
     * The stream will encrypt communication that goes over the wire.
     * E.g. EMail, Chat...
     */
    COMMUNICATIONS,
    /**
     * The stream will encrypt data at rest.
     * E.g. Encrypted backup...
     */
    STORAGE,
    /**
     * The stream will use keys with either flags to encrypt the data.
     */
    ANY
}