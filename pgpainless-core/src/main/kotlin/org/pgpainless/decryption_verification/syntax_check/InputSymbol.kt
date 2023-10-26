// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check

enum class InputSymbol {
    /** A [PGPLiteralData] packet. */
    LITERAL_DATA,
    /** A [PGPSignatureList] object. */
    SIGNATURE,
    /** A [PGPOnePassSignatureList] object. */
    ONE_PASS_SIGNATURE,
    /**
     * A [PGPCompressedData] packet. The contents of this packet MUST form a valid OpenPGP message,
     * so a nested PDA is opened to verify its nested packet sequence.
     */
    COMPRESSED_DATA,
    /**
     * A [PGPEncryptedDataList] object. This object combines multiple ESKs and the corresponding
     * Symmetrically Encrypted (possibly Integrity Protected) Data packet.
     */
    ENCRYPTED_DATA,
    /**
     * Marks the end of a (sub-) sequence. This input is given if the end of an OpenPGP message is
     * reached. This might be the case for the end of the whole ciphertext, or the end of a packet
     * with nested contents (e.g. the end of a Compressed Data packet).
     */
    END_OF_SEQUENCE
}
