// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import java.io.IOException
import java.io.InputStream
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.api.OpenPGPImplementation
import org.pgpainless.PGPainless
import org.pgpainless.util.ArmorUtils

/**
 * Inspect an OpenPGP message to determine IDs of its encryption keys or whether it is passphrase
 * protected.
 */
class MessageInspector(val api: PGPainless = PGPainless.getInstance()) {

    /**
     * Info about an OpenPGP message.
     *
     * @param keyIdentifiers List of recipient [KeyIdentifiers][KeyIdentifier] for whom the message
     *   is encrypted.
     * @param isPassphraseEncrypted true, if the message is encrypted for a passphrase
     * @param isSignedOnly true, if the message is not encrypted, but signed using OnePassSignatures
     */
    data class EncryptionInfo(
        val keyIdentifiers: List<KeyIdentifier>,
        val isPassphraseEncrypted: Boolean,
        val isSignedOnly: Boolean
    ) {

        val isEncrypted: Boolean
            get() = isPassphraseEncrypted || keyIds.isNotEmpty()

        val keyIds: List<Long> = keyIdentifiers.map { it.keyId }
    }

    /**
     * Parses parts of the provided OpenPGP message in order to determine which keys were used to
     * encrypt it.
     *
     * @param message OpenPGP message
     * @return encryption info
     * @throws PGPException in case the message is broken
     * @throws IOException in case of an IO error
     */
    @Throws(PGPException::class, IOException::class)
    fun determineEncryptionInfoForMessage(message: String): EncryptionInfo =
        determineEncryptionInfoForMessage(message.byteInputStream())

    /**
     * Parses parts of the provided OpenPGP message in order to determine which keys were used to
     * encrypt it. Note: This method does not rewind the passed in Stream, so you might need to take
     * care of that yourselves.
     *
     * @param inputStream openpgp message
     * @return encryption information
     * @throws IOException in case of an IO error
     * @throws PGPException if the message is broken
     */
    @Throws(PGPException::class, IOException::class)
    fun determineEncryptionInfoForMessage(inputStream: InputStream): EncryptionInfo {
        return processMessage(ArmorUtils.getDecoderStream(inputStream))
    }

    @Throws(PGPException::class, IOException::class)
    private fun processMessage(inputStream: InputStream): EncryptionInfo {
        var objectFactory = api.implementation.pgpObjectFactory(inputStream)

        var n: Any?
        while (objectFactory.nextObject().also { n = it } != null) {
            when (val next = n!!) {
                is PGPOnePassSignatureList -> {
                    if (!next.isEmpty) {
                        return EncryptionInfo(
                            listOf(), isPassphraseEncrypted = false, isSignedOnly = true)
                    }
                }
                is PGPEncryptedDataList -> {
                    var isPassphraseEncrypted = false
                    val keyIdentifiers = mutableListOf<KeyIdentifier>()
                    for (encryptedData in next) {
                        if (encryptedData is PGPPublicKeyEncryptedData) {
                            keyIdentifiers.add(encryptedData.keyIdentifier)
                        } else if (encryptedData is PGPPBEEncryptedData) {
                            isPassphraseEncrypted = true
                        }
                    }
                    // Data is encrypted, we cannot go deeper
                    return EncryptionInfo(keyIdentifiers, isPassphraseEncrypted, false)
                }
                is PGPCompressedData -> {
                    objectFactory =
                        OpenPGPImplementation.getInstance()
                            .pgpObjectFactory(PGPUtil.getDecoderStream(next.dataStream))
                    continue
                }
                is PGPLiteralData -> {
                    break
                }
            }
        }
        return EncryptionInfo(listOf(), isPassphraseEncrypted = false, isSignedOnly = false)
    }
}
