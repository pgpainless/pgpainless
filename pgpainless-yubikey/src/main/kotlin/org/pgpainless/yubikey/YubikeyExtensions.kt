// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.yubikey

import com.yubico.yubikit.core.keys.PrivateKeyValues
import com.yubico.yubikit.openpgp.KeyRef
import com.yubico.yubikit.openpgp.OpenPgpSession
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPPrivateKey
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter

/**
 * Writes the private key bytes of an [OpenPGPPrivateKey] to the slot identified by the provided
 * [KeyRef]. This method requires the session to have a verified admin pin.
 */
internal fun OpenPgpSession.writePrivateKey(key: OpenPGPPrivateKey, keyRef: KeyRef) {
    writePrivateKey(key.keyPair.privateKey, keyRef)
}

/**
 * Writes the private key bytes of a [PGPPrivateKey] to the slot identified by the provided
 * [KeyRef]. This method requires the session to have a verified admin pin.
 */
internal fun OpenPgpSession.writePrivateKey(key: PGPPrivateKey, keyRef: KeyRef) {
    val privateKey = JcaPGPKeyConverter().setProvider(BouncyCastleProvider()).getPrivateKey(key)
    putKey(keyRef, PrivateKeyValues.fromPrivateKey(privateKey))
}

/**
 * Writes the 20-octet fingerprint of an OpenPGP key to the slot identified by the provided
 * [KeyRef]. This method requires the session to have a verified admin pin.
 */
internal fun OpenPgpSession.writeFingerprint(
    key: OpenPGPCertificate.OpenPGPComponentKey,
    keyRef: KeyRef
) = writeFingerprint(key.pgpPublicKey, keyRef)

/**
 * Writes the 20-octet fingerprint of an OpenPGP key to the slot identified by the provided
 * [KeyRef]. This method requires the session to have a verified admin pin.
 */
internal fun OpenPgpSession.writeFingerprint(key: PGPPublicKey, keyRef: KeyRef) {
    setFingerprint(keyRef, key.fingerprint)
}

/**
 * Writes the key generation time of an OpenPGP key to the slot identified by the provided [KeyRef].
 * This method requires the session to have a verified admin pin.
 */
internal fun OpenPgpSession.writeGenerationTime(
    key: OpenPGPCertificate.OpenPGPComponentKey,
    keyRef: KeyRef
) = writeGenerationTime(key.pgpPublicKey, keyRef)

/**
 * Writes the key generation time of an OpenPGP key to the slot identified by the provided [KeyRef].
 * This method requires the session to have a verified admin pin.
 */
internal fun OpenPgpSession.writeGenerationTime(key: PGPPublicKey, keyRef: KeyRef) {
    val time = (key.publicKeyPacket.time.time / 1000).toInt()
    setGenerationTime(keyRef, time)
}
