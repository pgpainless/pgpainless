// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.bouncycastle.extensions

import java.io.OutputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.PacketFormat
import org.bouncycastle.openpgp.PGPOnePassSignature
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.pgpainless.algorithm.OpenPGPKeyVersion

/**
 * Return the [OpenPGPComponentKey] that issued the given [PGPOnePassSignature].
 *
 * @param ops one pass signature
 */
fun OpenPGPCertificate.getSigningKeyFor(ops: PGPOnePassSignature): OpenPGPComponentKey? =
    this.getKey(ops.keyIdentifier)

/** Return the [OpenPGPKeyVersion] of the certificates primary key. */
fun OpenPGPCertificate.getKeyVersion(): OpenPGPKeyVersion = primaryKey.getKeyVersion()

/** Return the [OpenPGPKeyVersion] of the component key. */
fun OpenPGPComponentKey.getKeyVersion(): OpenPGPKeyVersion = OpenPGPKeyVersion.from(this.version)

/**
 * ASCII-armor-encode the certificate into the given [OutputStream].
 *
 * @param outputStream output stream
 * @param format packet length encoding format, defaults to [PacketFormat.ROUNDTRIP]
 */
fun OpenPGPCertificate.asciiArmor(
    outputStream: OutputStream,
    format: PacketFormat = PacketFormat.ROUNDTRIP
) {
    outputStream.write(toAsciiArmoredString(format).encodeToByteArray())
}

/**
 * ASCII-armor-encode the certificate into the given [OutputStream].
 *
 * @param outputStream output stream
 * @param format packet length encoding format, defaults to [PacketFormat.ROUNDTRIP]
 * @param armorBuilder builder for the ASCII armored output stream
 */
fun OpenPGPCertificate.asciiArmor(
    outputStream: OutputStream,
    format: PacketFormat,
    armorBuilder: ArmoredOutputStream.Builder
) {
    outputStream.write(toAsciiArmoredString(format, armorBuilder).encodeToByteArray())
}

fun OpenPGPCertificate.encode(
    outputStream: OutputStream,
    format: PacketFormat = PacketFormat.ROUNDTRIP
) {
    outputStream.write(getEncoded(format))
}
