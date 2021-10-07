// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

public enum EncryptionPurpose {
    /**
     * The stream will encrypt communication that goes over the wire.
     * Eg. EMail, Chat...
     */
    COMMUNICATIONS,
    /**
     * The stream will encrypt data that is stored on disk.
     * Eg. Encrypted backup...
     */
    STORAGE,
    /**
     * The stream will use keys with either flags to encrypt the data.
     */
    STORAGE_AND_COMMUNICATIONS
}
