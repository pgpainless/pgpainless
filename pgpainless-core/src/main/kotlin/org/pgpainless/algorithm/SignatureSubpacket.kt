// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

import org.bouncycastle.bcpg.SignatureSubpacketTags.*

/**
 * Enumeration of possible subpackets that might be found in the hashed and unhashed area of an OpenPGP signature.
 *
 * See [RFC4880: Signature Subpacket Specification](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)
 */
enum class SignatureSubpacket(val code: Int) {
    /**
     * The time the signature was made.
     * MUST be present in the hashed area of the signature.
     *
     * See [Signature Creation Time](https://tools.ietf.org/html/rfc4880#section-5.2.3.4)
     */
    signatureCreationTime(2),

    /**
     * The validity period of the signature.  This is the number of seconds
     * after the signature creation time that the signature expires.  If
     * this is not present or has a value of zero, it never expires.
     *
     * See [Signature Expiration Time](https://tools.ietf.org/html/rfc4880#section-5.2.3.10)
     */
    signatureExpirationTime(3),

    /**
     * Denotes whether the signature is exportable for other users.
     *
     * See [Exportable Certification](https://tools.ietf.org/html/rfc4880#section-5.2.3.11)
     */
    exportableCertification(4),

    /**
     * Signer asserts that the key is not only valid but also trustworthy at
     * the specified level.  Level 0 has the same meaning as an ordinary
     * validity signature.  Level 1 means that the signed key is asserted to
     * be a valid, trusted introducer, with the 2nd octet of the body
     * specifying the degree of trust.  Level 2 means that the signed key is
     * asserted to be trusted to issue level 1 trust signatures, i.e., that
     * it is a "meta introducer".  Generally, a level n trust signature
     * asserts that a key is trusted to issue level n-1 trust signatures.
     * The trust amount is in a range from 0-255, interpreted such that
     * values less than 120 indicate partial trust and values of 120 or
     * greater indicate complete trust.  Implementations SHOULD emit values
     * of 60 for partial trust and 120 for complete trust.
     *
     * See [Trust Signature](https://tools.ietf.org/html/rfc4880#section-5.2.3.13)
     */
    trustSignature(5),

    /**
     * Used in conjunction with trust Signature packets (of level greater 0) to
     * limit the scope of trust that is extended.  Only signatures by the
     * target key on User IDs that match the regular expression in the body
     * of this packet have trust extended by the trust Signature subpacket.
     * The regular expression uses the same syntax as the Henry Spencer's
     * "almost public domain" regular expression [REGEX] package.  A
     * description of the syntax is found in Section 8 below.
     *
     * See [Regular Expression](https://tools.ietf.org/html/rfc4880#section-5.2.3.14)
     */
    regularExpression(6),

    /**
     * Signature's revocability status.  The packet body contains a Boolean
     * flag indicating whether the signature is revocable.  Signatures that
     * are not revocable have any later revocation signatures ignored.  They
     * represent a commitment by the signer that he cannot revoke his
     * signature for the life of his key.  If this packet is not present,
     * the signature is revocable.
     *
     * See [Revocable](https://tools.ietf.org/html/rfc4880#section-5.2.3.12)
     */
    revocable(7),

    /**
     * The validity period of the key.  This is the number of seconds after
     * the key creation time that the key expires.  If this is not present
     * or has a value of zero, the key never expires.  This is found only on
     * a self-signature.
     *
     * See [Key Expiration Time](https://tools.ietf.org/html/rfc4880#section-5.2.3.6)
     */
    keyExpirationTime(9),

    /**
     * Placeholder for backwards compatibility.
     */
    placeholder(10),

    /**
     *  Symmetric algorithm numbers that indicate which algorithms the keyholder
     *  prefers to use.  The subpackets body is an ordered list of
     *  octets with the most preferred listed first.  It is assumed that only
     *  algorithms listed are supported by the recipient's software.
     *  This is only found on a self-signature.
     *
     * See [Preferred Symmetric Algorithms](https://tools.ietf.org/html/rfc4880#section-5.2.3.7)
     */
    preferredSymmetricAlgorithms(11),

    /**
     * Authorizes the specified key to issue revocation signatures for this
     * key.  Class octet must have bit 0x80 set.  If the bit 0x40 is set,
     * then this means that the revocation information is sensitive.  Other
     * bits are for future expansion to other kinds of authorizations.  This
     * is found on a self-signature.
     *
     * If the "sensitive" flag is set, the keyholder feels this subpacket
     * contains private trust information that describes a real-world
     * sensitive relationship.  If this flag is set, implementations SHOULD
     * NOT export this signature to other users except in cases where the
     * data needs to be available: when the signature is being sent to the
     * designated revoker, or when it is accompanied by a revocation
     * signature from that revoker.  Note that it may be appropriate to
     * isolate this subpacket within a separate signature so that it is not
     * combined with other subpackets that need to be exported.
     *
     * See [Revocation Key](https://tools.ietf.org/html/rfc4880#section-5.2.3.15)
     */
    revocationKey(12),

    /**
     * The OpenPGP Key ID of the key issuing the signature.
     *
     * See [Issuer Key ID](https://tools.ietf.org/html/rfc4880#section-5.2.3.5)
     */
    issuerKeyId(16),

    /**
     * This subpacket describes a "notation" on the signature that the
     * issuer wishes to make.  The notation has a name and a value, each of
     * which are strings of octets.  There may be more than one notation in
     * a signature.  Notations can be used for any extension the issuer of
     * the signature cares to make.  The "flags" field holds four octets of
     * flags.
     *
     * See [Notation Data](https://tools.ietf.org/html/rfc4880#section-5.2.3.16)
     */
    notationData(20),

    /**
     * Message digest algorithm numbers that indicate which algorithms the
     * keyholder prefers to receive.  Like the preferred symmetric
     * algorithms, the list is ordered.
     * This is only found on a self-signature.
     *
     * See [Preferred Hash Algorithms](https://tools.ietf.org/html/rfc4880#section-5.2.3.8)
     */
    preferredHashAlgorithms(21),

    /**
     * Compression algorithm numbers that indicate which algorithms the
     * keyholder prefers to use.  Like the preferred symmetric algorithms, the
     * list is ordered. If this subpacket is not included, ZIP is preferred.
     * A zero denotes that uncompressed data is preferred; the keyholder's
     * software might have no compression software in that implementation.
     * This is only found on a self-signature.
     *
     * See [Preferred Compressio Algorithms](https://tools.ietf.org/html/rfc4880#section-5.2.3.9)
     */
    preferredCompressionAlgorithms(22),

    /**
     * This is a list of one-bit flags that indicate preferences that the
     * keyholder has about how the key is handled on a key server.  All
     * undefined flags MUST be zero.
     * This is found only on a self-signature.
     *
     * See [Key Server Preferences](https://tools.ietf.org/html/rfc4880#section-5.2.3.17)
     */
    keyServerPreferences(23),

    /**
     * This is a URI of a key server that the keyholder prefers be used for
     * updates.  Note that keys with multiple User IDs can have a preferred
     * key server for each User ID.  Note also that since this is a URI, the
     * key server can actually be a copy of the key retrieved by ftp, http,
     * finger, etc.
     *
     * See [Preferred Key Server](https://tools.ietf.org/html/rfc4880#section-5.2.3.18)
     */
    preferredKeyServers(24),

    /**
     * This is a flag in a User ID's self-signature that states whether this
     * User ID is the main User ID for this key.  It is reasonable for an
     * implementation to resolve ambiguities in preferences, etc. by
     * referring to the primary User ID.  If this flag is absent, its value
     * is zero.  If more than one User ID in a key is marked as primary, the
     * implementation may resolve the ambiguity in any way it sees fit, but
     * it is RECOMMENDED that priority be given to the User ID with the most
     * recent self-signature.
     *
     * When appearing on a self-signature on a User ID packet, this
     * subpacket applies only to User ID packets.  When appearing on a
     * self-signature on a User Attribute packet, this subpacket applies
     * only to User Attribute packets.  That is to say, there are two
     * different and independent "primaries" -- one for User IDs, and one
     * for User Attributes.
     *
     * See [Primary User-ID](https://tools.ietf.org/html/rfc4880#section-5.2.3.19)
     */
    primaryUserId(25),

    /**
     * This subpacket contains a URI of a document that describes the policy
     * under which the signature was issued.
     *
     * See [Policy URL](https://tools.ietf.org/html/rfc4880#section-5.2.3.20)
     */
    policyUrl(26),

    /**
     * This subpacket contains a list of binary flags that hold information
     * about a key.  It is a string of octets, and an implementation MUST
     * NOT assume a fixed size.  This is so it can grow over time.  If a
     * list is shorter than an implementation expects, the unstated flags
     * are considered to be zero.
     *
     * See [Key Flags](https://tools.ietf.org/html/rfc4880#section-5.2.3.21)
     */
    keyFlags(27),

    /**
     * This subpacket allows a keyholder to state which User ID is
     * responsible for the signing.  Many keyholders use a single key for
     * different purposes, such as business communications as well as
     * personal communications.  This subpacket allows such a keyholder to
     * state which of their roles is making a signature.
     *
     * See [Signer's User ID](https://tools.ietf.org/html/rfc4880#section-5.2.3.22)
     */
    signerUserId(28),

    /**
     * This subpacket is used only in key revocation and certification
     * revocation signatures.  It describes the reason why the key or
     * certificate was revoked.
     *
     * The first octet contains a machine-readable code that denotes the
     * reason for the revocation:
     *
     *         0  - No reason specified (key revocations or cert revocations)
     *         1  - Key is superseded (key revocations)
     *         2  - Key material has been compromised (key revocations)
     *         3  - Key is retired and no longer used (key revocations)
     *         32 - User ID information is no longer valid (cert revocations)
     *    100-110 - Private Use
     *
     * See [Reason for Revocation](https://tools.ietf.org/html/rfc4880#section-5.2.3.23)
     */
    revocationReason(29),

    /**
     * The Features subpacket denotes which advanced OpenPGP features a
     * user's implementation supports.  This is so that as features are
     * added to OpenPGP that cannot be backwards-compatible, a user can
     * state that they can use that feature.  The flags are single bits that
     * indicate that a given feature is supported.
     *
     * This subpacket is similar to a preferences subpacket, and only
     * appears in a self-signature.
     *
     * See [Features](https://tools.ietf.org/html/rfc4880#section-5.2.3.24)
     */
    features(30),

    /**
     * This subpacket identifies a specific target signature to which a
     * signature refers.  For revocation signatures, this subpacket
     * provides explicit designation of which signature is being revoked.
     * For a third-party or timestamp signature, this designates what
     * signature is signed.  All arguments are an identifier of that target
     * signature.
     *
     * The N octets of hash data MUST be the size of the hash of the
     * signature.  For example, a target signature with a SHA-1 hash MUST
     * have 20 octets of hash data.
     *
     * See [Signature Target](https://tools.ietf.org/html/rfc4880#section-5.2.3.25)
     */
    signatureTarget(31),

    /**
     * This subpacket contains a complete Signature packet body as
     * specified in Section 5.2 above.  It is useful when one signature
     * needs to refer to, or be incorporated in, another signature.
     *
     * See [Embedded Signature](https://tools.ietf.org/html/rfc4880#section-5.2.3.26)
     */
    embeddedSignature(32),

    /**
     * The OpenPGP Key fingerprint of the key issuing the signature.  This
     * subpacket SHOULD be included in all signatures.  If the version of
     * the issuing key is 4 and an Issuer subpacket is also included in the
     * signature, the key ID of the Issuer subpacket MUST match the low 64
     * bits of the fingerprint.
     *
     * Note that the length N of the fingerprint for a version 4 key is 20
     * octets; for a version 5 key N is 32.
     *
     * See [Issuer Fingerprint](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.28)
     */
    issuerFingerprint(33),

    /**
     * AEAD algorithm numbers that indicate which AEAD algorithms the
     * keyholder prefers to use.  The subpackets body is an ordered list of
     * octets with the most preferred listed first.  It is assumed that only
     * algorithms listed are supported by the recipient's software.
     * This is only found on a self-signature.
     * Note that support for the AEAD Encrypted Data packet in the general
     * is indicated by a Feature Flag.
     *
     * See [Preferred AEAD Algorithms](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.8)
     */
    preferredAEADAlgorithms(39),

    /**
     * The OpenPGP Key fingerprint of the intended recipient primary key.
     * If one or more subpackets of this type are included in a signature,
     * it SHOULD be considered valid only in an encrypted context, where the
     * key it was encrypted to is one of the indicated primary keys, or one
     * of their subkeys.  This can be used to prevent forwarding a signature
     * outside its intended, encrypted context.
     *
     * Note that the length N of the fingerprint for a version 4 key is 20
     * octets; for a version 5 key N is 32.
     *
     * See [Intended Recipient Fingerprint](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.29)
     */
    intendedRecipientFingerprint(35),

    /**
     * This subpacket MUST only appear as a hashed subpacket of an
     * Attestation Key Signature.  It has no meaning in any other signature
     * type.  It is used by the primary key to attest to a set of third-
     * party certifications over the associated User ID or User Attribute.
     * This enables the holder of an OpenPGP primary key to mark specific
     * third-party certifications as re-distributable with the rest of the
     * Transferable Public Key (see the "No-modify" flag in "Key Server
     * Preferences", above).  Implementations MUST include exactly one
     * Attested Certification subpacket in any generated Attestation Key
     * Signature.
     *
     * See [Attested Certification](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.30)
     */
    attestedCertification(37)
    ;
    
    companion object {
        
        /**
         * Return the [SignatureSubpacket] that corresponds to the provided id.
         * If an unmatched code is presented, return null.
         *
         * @param code id
         * @return signature subpacket
         */
        @JvmStatic
        fun fromCode(code: Int): SignatureSubpacket? {
            return values().firstOrNull { 
                it.code == code
            }
        }

        /**
         * Return the [SignatureSubpacket] that corresponds to the provided code.
         *
         * @param code code
         * @return signature subpacket
         * @throws NoSuchElementException in case of an unmatched subpacket tag
         */
        @JvmStatic
        fun requireFromCode(code: Int): SignatureSubpacket {
            return fromCode(code) ?:
            throw NoSuchElementException("No SignatureSubpacket tag found with code $code")
        }

        /**
         * Convert an array of signature subpacket tags into a list of [SignatureSubpacket SignatureSubpackets].
         *
         * @param codes array of codes
         * @return list of subpackets
         */
        @JvmStatic
        fun fromCodes(vararg codes: Int): List<SignatureSubpacket> {
            return codes.toList().mapNotNull {
                fromCode(it)
            }
        }
    }
}