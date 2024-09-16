// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

import org.bouncycastle.openpgp.PGPSignature

/**
 * Enum that enlists all the Signature Types defined in rfc4880 section 5.2.1 See [PGPSignature] for
 * comparison.
 *
 * See [rfc4880 §5.2.1. Signature Types](https://tools.ietf.org/html/rfc4880#section-5.11)
 */
enum class SignatureType(val code: Int) {

    /**
     * Signature of a binary document. This means the signer owns it, created it, or certifies that
     * it has not been modified.
     */
    BINARY_DOCUMENT(0x00),

    /**
     * Signature of a canonical text document. This means the signer owns it, created it, or
     * certifies that it has not been modified. The signature is calculated over the text data with
     * its line endings converted to `<CR><LF>`.
     */
    CANONICAL_TEXT_DOCUMENT(0x01),

    /**
     * Standalone signature. This signature is a signature of only its own subpacket contents. It is
     * calculated identically to a signature over a zero-length binary document. Note that it
     * doesn't make sense to have a V3 standalone signature.
     */
    STANDALONE(0x02),

    /**
     * Generic certification of a User ID and Public-Key packet. The issuer of this certification
     * does not make any particular assertion as to how well the certifier has checked that the
     * owner of the key is in fact the person described by the User ID.
     */
    GENERIC_CERTIFICATION(0x10),

    /**
     * Persona certification of a User ID and Public-Key packet. The issuer of this certification
     * has not done any verification of the claim that the owner of this key is the User ID
     * specified.
     */
    NO_CERTIFICATION(0x11),

    /**
     * Casual certification of a User ID and Public-Key packet. The issuer of this certification has
     * done some casual verification of the claim of identity.
     */
    CASUAL_CERTIFICATION(0x12),

    /**
     * Positive certification of a User ID and Public-Key packet. The issuer of this certification
     * has done substantial verification of the claim of identity.
     */
    POSITIVE_CERTIFICATION(0x13),

    /**
     * Subkey Binding Signature. This signature is a statement by the top-level signing key that
     * indicates that it owns the subkey. This signature is calculated directly on the primary key
     * and subkey, and not on any User ID or other packets. A signature that binds a signing subkey
     * MUST have an Embedded Signature subpacket in this binding signature that contains a
     * [#PRIMARYKEY_BINDING] signature made by the signing subkey on the primary key and subkey.
     */
    SUBKEY_BINDING(0x18),

    /**
     * Primary Key Binding Signature This signature is a statement by a signing subkey, indicating
     * that it is owned by the primary key and subkey. This signature is calculated the same way as
     * a [#SUBKEY_BINDING] signature: directly on the primary key and subkey, and not on any User ID
     * or other packets.
     */
    PRIMARYKEY_BINDING(0x19),

    /**
     * Signature directly on a key This signature is calculated directly on a key. It binds the
     * information in the Signature subpackets to the key, and is appropriate to be used for
     * subpackets that provide information about the key, such as the Revocation Key subpacket. It
     * is also appropriate for statements that non-self certifiers want to make about the key
     * itself, rather than the binding between a key and a name.
     */
    DIRECT_KEY(0x1f),

    /**
     * Key revocation signature The signature is calculated directly on the key being revoked. A
     * revoked key is not to be used. Only revocation signatures by the key being revoked, or by an
     * authorized revocation key, should be considered valid revocation signatures.
     */
    KEY_REVOCATION(0x20),

    /**
     * Subkey revocation signature The signature is calculated directly on the subkey being revoked.
     * A revoked subkey is not to be used. Only revocation signatures by the top-level signature key
     * that is bound to this subkey, or by an authorized revocation key, should be considered valid
     * revocation signatures.
     */
    SUBKEY_REVOCATION(0x28),

    /**
     * Certification revocation signature This signature revokes an earlier User ID certification
     * signature (signature class 0x10 through 0x13) or signature [#DIRECT_KEY]. It should be issued
     * by the same key that issued the revoked signature or an authorized revocation key. The
     * signature is computed over the same data as the certificate that it revokes, and should have
     * a later creation date than that certificate.
     */
    CERTIFICATION_REVOCATION(0x30),

    /** Timestamp signature. This signature is only meaningful for the timestamp contained in it. */
    TIMESTAMP(0x40),

    /**
     * Third-Party Confirmation signature. This signature is a signature over some other OpenPGP
     * Signature packet(s). It is analogous to a notary seal on the signed data. A third-party
     * signature SHOULD include Signature Target subpacket(s) to give easy identification. Note that
     * we really do mean SHOULD. There are plausible uses for this (such as a blind party that only
     * sees the signature, not the key or source document) that cannot include a target subpacket.
     */
    THIRD_PARTY_CONFIRMATION(0x50);

    companion object {

        /**
         * Convert a numerical id into a [SignatureType].
         *
         * @param code numeric id
         * @return signature type enum
         */
        @JvmStatic
        fun fromCode(code: Int): SignatureType? {
            return values().firstOrNull { it.code == code }
        }

        /**
         * Convert a numerical id into a [SignatureType].
         *
         * @param code numeric id
         * @return signature type enum
         * @throws NoSuchElementException in case of an unmatched signature type code
         */
        @JvmStatic
        fun requireFromCode(code: Int): SignatureType {
            return fromCode(code)
                ?: throw NoSuchElementException(
                    "Signature type 0x${Integer.toHexString(code)} appears to be invalid.")
        }

        /**
         * Convert a numerical id into a [SignatureType].
         *
         * @param code numeric id
         * @return signature type enum
         * @throws IllegalArgumentException in case of an unmatched signature type code
         */
        @JvmStatic
        @Deprecated(
            "Deprecated in favor of requireFromCode",
            ReplaceWith("SignatureType.requireFromCode(code)"))
        fun valueOf(code: Int): SignatureType {
            try {
                return requireFromCode(code)
            } catch (e: NoSuchElementException) {
                throw IllegalArgumentException(e.message)
            }
        }

        @JvmStatic
        fun isRevocationSignature(signatureType: Int): Boolean {
            return isRevocationSignature(valueOf(signatureType))
        }

        @JvmStatic
        fun isRevocationSignature(signatureType: SignatureType): Boolean {
            return when (signatureType) {
                BINARY_DOCUMENT,
                CANONICAL_TEXT_DOCUMENT,
                STANDALONE,
                GENERIC_CERTIFICATION,
                NO_CERTIFICATION,
                CASUAL_CERTIFICATION,
                POSITIVE_CERTIFICATION,
                SUBKEY_BINDING,
                PRIMARYKEY_BINDING,
                DIRECT_KEY,
                TIMESTAMP,
                THIRD_PARTY_CONFIRMATION -> false
                KEY_REVOCATION,
                SUBKEY_REVOCATION,
                CERTIFICATION_REVOCATION -> true
                else -> throw IllegalArgumentException("Unknown signature type: $signatureType")
            }
        }
    }
}
