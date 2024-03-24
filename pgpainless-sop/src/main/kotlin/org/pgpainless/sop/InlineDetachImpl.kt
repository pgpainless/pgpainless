// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.util.io.Streams
import org.pgpainless.decryption_verification.OpenPgpInputStream
import org.pgpainless.decryption_verification.cleartext_signatures.ClearsignedMessageUtil
import org.pgpainless.exception.WrongConsumingMethodException
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.util.ArmoredOutputStreamFactory
import sop.ReadyWithResult
import sop.Signatures
import sop.exception.SOPGPException
import sop.operation.InlineDetach

/** Implementation of the `inline-detach` operation using PGPainless. */
class InlineDetachImpl : InlineDetach {

    private var armor = true

    override fun message(messageInputStream: InputStream): ReadyWithResult<Signatures> {
        return object : ReadyWithResult<Signatures>() {

            private val sigOut = ByteArrayOutputStream()

            override fun writeTo(messageOutputStream: OutputStream): Signatures {
                var pgpIn = OpenPgpInputStream(messageInputStream)
                if (pgpIn.isNonOpenPgp) {
                    throw SOPGPException.BadData("Data appears to be non-OpenPGP.")
                }
                var signatures: PGPSignatureList? = null

                // Handle ASCII armor
                if (pgpIn.isAsciiArmored) {
                    val armorIn = ArmoredInputStream(pgpIn)

                    // Handle cleartext signature framework
                    if (armorIn.isClearText) {
                        try {
                            signatures =
                                ClearsignedMessageUtil.detachSignaturesFromInbandClearsignedMessage(
                                    armorIn, messageOutputStream)
                            if (signatures.isEmpty) {
                                throw SOPGPException.BadData(
                                    "Data did not contain OpenPGP signatures.")
                            }
                        } catch (e: WrongConsumingMethodException) {
                            throw SOPGPException.BadData(e)
                        }
                    }

                    // else just dearmor
                    pgpIn = OpenPgpInputStream(armorIn)
                }

                // If data was not using cleartext signature framework
                if (signatures == null) {
                    if (!pgpIn.isBinaryOpenPgp) {
                        throw SOPGPException.BadData(
                            "Data was containing ASCII armored non-OpenPGP data.")
                    }

                    // handle binary OpenPGP data
                    var objectFactory =
                        ImplementationFactory.getInstance().getPGPObjectFactory(pgpIn)
                    var next: Any?

                    while (objectFactory.nextObject().also { next = it } != null) {

                        if (next is PGPOnePassSignatureList) {
                            // Skip over OPSs
                            continue
                        }

                        if (next is PGPLiteralData) {
                            // Write out contents of Literal Data packet
                            val literalIn = (next as PGPLiteralData).dataStream
                            Streams.pipeAll(literalIn, messageOutputStream)
                            literalIn.close()
                            continue
                        }

                        if (next is PGPCompressedData) {
                            // Decompress compressed data
                            try {
                                objectFactory =
                                    ImplementationFactory.getInstance()
                                        .getPGPObjectFactory((next as PGPCompressedData).dataStream)
                            } catch (e: PGPException) {
                                throw SOPGPException.BadData(
                                    "Cannot decompress PGPCompressedData", e)
                            }
                        }

                        if (next is PGPSignatureList) {
                            signatures = next as PGPSignatureList
                        }
                    }
                }

                if (signatures == null) {
                    throw SOPGPException.BadData("Data did not contain OpenPGP signatures.")
                }

                if (armor) {
                    ArmoredOutputStreamFactory.get(sigOut).use { armoredOut ->
                        signatures.forEach { it.encode(armoredOut) }
                    }
                } else {
                    signatures.forEach { it.encode(sigOut) }
                }

                return object : Signatures() {
                    override fun writeTo(outputStream: OutputStream) {
                        sigOut.writeTo(outputStream)
                    }
                }
            }
        }
    }

    override fun noArmor(): InlineDetach = apply { armor = false }
}
