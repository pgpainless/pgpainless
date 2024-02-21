// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>, 2021 Flowcrypt a.s.
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.info

import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.pgpainless.bouncycastle.extensions.getCurveName
import org.pgpainless.bouncycastle.extensions.hasDummyS2K
import org.pgpainless.bouncycastle.extensions.isDecrypted
import org.pgpainless.bouncycastle.extensions.isEncrypted

@Deprecated("Deprecated in favor of extension functions to PGPSecretKey and PGPPublicKey.")
class KeyInfo private constructor(val secretKey: PGPSecretKey?, val publicKey: PGPPublicKey) {

    constructor(secretKey: PGPSecretKey) : this(secretKey, secretKey.publicKey)

    constructor(publicKey: PGPPublicKey) : this(null, publicKey)

    /**
     * Return the name of the elliptic curve used by this key, or throw an
     * [IllegalArgumentException] if the key is not based on elliptic curves, or on an unknown
     * curve.
     */
    @Deprecated(
        "Deprecated in favor of calling getCurveName() on the PGPPublicKey itself.",
        ReplaceWith("publicKey.getCurveName()"))
    val curveName: String
        get() = publicKey.getCurveName()

    /**
     * Return true, if the secret key is encrypted. This method returns false, if the secret key is
     * null.
     */
    @Deprecated(
        "Deprecated in favor of calling isEncrypted() on the PGPSecretKey itself.",
        ReplaceWith("secretKey.isEncrypted()"))
    val isEncrypted: Boolean
        get() = secretKey?.isEncrypted() ?: false

    /**
     * Return true, if the secret key is decrypted. This method returns true, if the secret key is
     * null.
     */
    @Deprecated(
        "Deprecated in favor of calling isDecrypted() on the PGPSecretKey itself.",
        ReplaceWith("secretKey.isDecrypted()"))
    val isDecrypted: Boolean
        get() = secretKey?.isDecrypted() ?: true

    /**
     * Return true, if the secret key is using the GNU_DUMMY_S2K s2k type. This method returns
     * false, if the secret key is null.
     */
    @Deprecated(
        "Deprecated in favor of calling hasDummyS2K() on the PGPSecretKey itself.",
        ReplaceWith("secretKey.hasDummyS2K()"))
    val hasDummyS2K: Boolean
        @JvmName("hasDummyS2K") get() = secretKey?.hasDummyS2K() ?: false

    companion object {
        @JvmStatic
        @Deprecated(
            "Deprecated in favor of calling isEncrypted() on the PGPSecretKey itself.",
            ReplaceWith("secretKey.isEncrypted()"))
        fun isEncrypted(secretKey: PGPSecretKey?) = secretKey.isEncrypted()

        @JvmStatic
        @Deprecated(
            "Deprecated in favor of calling isDecrypted() on the PGPSecretKey itself.",
            ReplaceWith("secretKey.isDecrypted()"))
        fun isDecrypted(secretKey: PGPSecretKey?) = secretKey.isDecrypted()

        @JvmStatic
        @Deprecated(
            "Deprecated in favor of calling hasDummyS2K() on the PGPSecretKey itself.",
            ReplaceWith("secretKey.hasDummyS2K()"))
        fun hasDummyS2K(secretKey: PGPSecretKey?) = secretKey.hasDummyS2K()
    }
}
