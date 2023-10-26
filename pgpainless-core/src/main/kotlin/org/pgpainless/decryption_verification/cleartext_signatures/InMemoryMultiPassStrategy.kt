// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.cleartext_signatures

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * Implementation of the [MultiPassStrategy]. This class keeps the read data in memory by caching
 * the data inside a [ByteArrayOutputStream].
 *
 * Note, that this class is suitable and efficient for processing small amounts of data. For larger
 * data like encrypted files, use of the [WriteToFileMultiPassStrategy] is recommended to prevent
 * [OutOfMemoryError] and other issues.
 */
class InMemoryMultiPassStrategy : MultiPassStrategy {

    private val cache = ByteArrayOutputStream()

    override val messageOutputStream: ByteArrayOutputStream
        get() = cache

    override val messageInputStream: ByteArrayInputStream
        get() = ByteArrayInputStream(getBytes())

    fun getBytes(): ByteArray = messageOutputStream.toByteArray()
}
