// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.security.InvalidAlgorithmParameterException
import java.security.NoSuchAlgorithmException
import java.util.*
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.pgpainless.util.Passphrase

interface KeyRingBuilderInterface<B : KeyRingBuilderInterface<B>> {

    fun setPrimaryKey(keySpec: KeySpec): B

    fun setPrimaryKey(builder: KeySpecBuilder): B = setPrimaryKey(builder.build())

    fun addSubkey(keySpec: KeySpec): B

    fun addSubkey(builder: KeySpecBuilder): B = addSubkey(builder.build())

    fun addUserId(userId: CharSequence): B

    fun addUserId(userId: ByteArray): B

    fun setExpirationDate(expirationDate: Date?): B

    fun setPassphrase(passphrase: Passphrase): B

    @Throws(
        NoSuchAlgorithmException::class,
        PGPException::class,
        InvalidAlgorithmParameterException::class)
    fun build(): PGPSecretKeyRing
}
