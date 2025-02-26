// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key

import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPPrivateKey

/**
 * Tuple class used to identify a subkey (component key) by fingerprints of the certificate, as well
 * as the component keys fingerprint.
 */
class SubkeyIdentifier(
    /**
     * Fingerprint of the certificate.
     */
    val certificateFingerprint: OpenPgpFingerprint,
    /**
     * Fingerprint of the target component key.
     */
    val componentKeyFingerprint: OpenPgpFingerprint
) {

    /**
     * Constructor for a [SubkeyIdentifier] pointing to the primary key identified by the
     * [certificateFingerprint].
     *
     * @param certificateFingerprint primary key fingerprint
     */
    constructor(
        certificateFingerprint: OpenPgpFingerprint
    ) : this(certificateFingerprint, certificateFingerprint)

    /**
     * Constructor for a [SubkeyIdentifier] pointing to the primary key of the given [PGPKeyRing].
     *
     * @param certificate certificate
     */
    constructor(certificate: PGPKeyRing) : this(certificate.publicKey)

    /**
     * Constructor for a [SubkeyIdentifier] pointing to the given [primaryKey].
     *
     * @param primaryKey primary key
     */
    constructor(primaryKey: PGPPublicKey) : this(OpenPgpFingerprint.of(primaryKey))

    /**
     * Constructor for a [SubkeyIdentifier] pointing to a component key (identified by
     * [componentKeyId]) from the given [certificate].
     */
    @Deprecated("Pass in a KeyIdentifier instead of a keyId.")
    constructor(
        certificate: PGPKeyRing,
        componentKeyId: Long
    ) : this(certificate, KeyIdentifier(componentKeyId))

    /**
     * Constructor for a [SubkeyIdentifier] pointing to the given [componentKey].
     *
     * @param componentKey component key
     */
    constructor(
        componentKey: OpenPGPComponentKey
    ) : this(OpenPgpFingerprint.of(componentKey.certificate), OpenPgpFingerprint.of(componentKey))

    /** Constructor for a [SubkeyIdentifier] pointing to the given [componentKey]. */
    constructor(componentKey: OpenPGPPrivateKey) : this(componentKey.secretKey)

    /**
     * Constructor for a [SubkeyIdentifier] pointing to a component key (identified by the
     * [componentKeyFingerprint]) of the given [certificate].
     *
     * @param certificate certificate
     * @param componentKeyFingerprint fingerprint of the component key
     */
    constructor(
        certificate: PGPKeyRing,
        componentKeyFingerprint: OpenPgpFingerprint
    ) : this(OpenPgpFingerprint.of(certificate), componentKeyFingerprint)

    /**
     * Constructor for a [SubkeyIdentifier] pointing to a component key (identified by the
     * [componentKeyIdentifier]) of the given [certificate].
     *
     * @param certificate certificate
     * @param componentKeyIdentifier identifier of the component key
     */
    constructor(
        certificate: PGPKeyRing,
        componentKeyIdentifier: KeyIdentifier
    ) : this(
        OpenPgpFingerprint.of(certificate),
        OpenPgpFingerprint.of(
            certificate.getPublicKey(componentKeyIdentifier)
                ?: throw NoSuchElementException(
                    "OpenPGP key does not contain subkey $componentKeyIdentifier")))

    @Deprecated(
        "Use certificateFingerprint instead.", replaceWith = ReplaceWith("certificateFingerprint"))
    val primaryKeyFingerprint: OpenPgpFingerprint = certificateFingerprint

    @Deprecated(
        "Use componentKeyFingerprint instead.",
        replaceWith = ReplaceWith("componentKeyFingerprint"))
    val subkeyFingerprint: OpenPgpFingerprint = componentKeyFingerprint

    /** [KeyIdentifier] of the component key. */
    val keyIdentifier = componentKeyFingerprint.keyIdentifier

    /** [KeyIdentifier] of the component key. */
    val componentKeyIdentifier = keyIdentifier

    /** [KeyIdentifier] of the primary key of the certificate the component key belongs to. */
    val certificateIdentifier = certificateFingerprint.keyIdentifier

    /** Key-ID of the component key. */
    @Deprecated("Use of key-ids is discouraged.") val keyId = keyIdentifier.keyId

    /** Fingerprint of the component key. */
    val fingerprint = componentKeyFingerprint

    /** Key-ID of the component key. */
    @Deprecated("Use of key-ids is discouraged.") val subkeyId = componentKeyIdentifier.keyId

    /** Key-ID of the primary key of the certificate the component key belongs to. */
    @Deprecated("Use of key-ids is discouraged.") val primaryKeyId = certificateIdentifier.keyId

    /** True, if the component key is the primary key. */
    val isPrimaryKey = certificateIdentifier.matches(componentKeyIdentifier)

    /**
     * Return true, if the provided [fingerprint] matches either the [certificateFingerprint]
     * or [componentKeyFingerprint].
     */
    fun matches(fingerprint: OpenPgpFingerprint) =
        certificateFingerprint == fingerprint || componentKeyFingerprint == fingerprint

    override fun equals(other: Any?): Boolean {
        if (other == null) {
            return false
        }
        if (this === other) {
            return true
        }
        if (other !is SubkeyIdentifier) {
            return false
        }

        return certificateFingerprint == other.certificateFingerprint &&
            componentKeyFingerprint == other.componentKeyFingerprint
    }

    override fun hashCode(): Int {
        return certificateFingerprint.hashCode() + 31 * componentKeyFingerprint.hashCode()
    }

    override fun toString(): String = "$componentKeyFingerprint $certificateFingerprint"
}
