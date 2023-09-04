// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check

enum class InputSymbol {
    /**
     * A [PGPLiteralData] packet.
     */
    LiteralData,
    /**
     * A [PGPSignatureList] object.
     */
    Signature,
    /**
     * A [PGPOnePassSignatureList] object.
     */
    OnePassSignature,
    /**
     * A [PGPCompressedData] packet.
     * The contents of this packet MUST form a valid OpenPGP message, so a nested PDA is opened to verify
     * its nested packet sequence.
     */
    CompressedData,
    /**
     * A [PGPEncryptedDataList] object.
     * This object combines multiple ESKs and the corresponding Symmetrically Encrypted
     * (possibly Integrity Protected) Data packet.
     */
    EncryptedData,
    /**
     * Marks the end of a (sub-) sequence.
     * This input is given if the end of an OpenPGP message is reached.
     * This might be the case for the end of the whole ciphertext, or the end of a packet with nested contents
     * (e.g. the end of a Compressed Data packet).
     */
    EndOfSequence
}