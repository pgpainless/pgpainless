/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.algorithm;

import static org.bouncycastle.bcpg.SignatureSubpacketTags.ATTESTED_CERTIFICATIONS;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.CREATION_TIME;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.EMBEDDED_SIGNATURE;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.EXPIRE_TIME;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.EXPORTABLE;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.FEATURES;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.INTENDED_RECIPIENT_FINGERPRINT;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.ISSUER_FINGERPRINT;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.ISSUER_KEY_ID;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.KEY_EXPIRE_TIME;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.KEY_FLAGS;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.KEY_SERVER_PREFS;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.NOTATION_DATA;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.PLACEHOLDER;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.POLICY_URL;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.PREFERRED_COMP_ALGS;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.PREFERRED_HASH_ALGS;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.PREFERRED_KEY_SERV;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.PREFERRED_SYM_ALGS;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.PRIMARY_USER_ID;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.REG_EXP;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.REVOCABLE;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.REVOCATION_KEY;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.REVOCATION_REASON;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.SIGNATURE_TARGET;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.SIGNER_USER_ID;
import static org.bouncycastle.bcpg.SignatureSubpacketTags.TRUST_SIG;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enumeration of possible subpackets that might be found in the hashed and unhashed area of an OpenPGP signature.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.1">RFC4880: Signature Subpacket Specification</a>
 */
public enum SignatureSubpacket {

    /**
     * The time the signature was made.
     * MUST be present in the hashed area of the signature.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.4">Signature Creation Time</a>
     */
    signatureCreationTime(CREATION_TIME),

    /**
     * The validity period of the signature.  This is the number of seconds
     * after the signature creation time that the signature expires.  If
     * this is not present or has a value of zero, it never expires.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.10">Signature Expiration Time</a>
     */
    signatureExpirationTime(EXPIRE_TIME),

    /**
     * Denotes whether or not the signature is exportable for other users.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.11">Exportable Certification</a>
     */
    exportableCertification(EXPORTABLE),

    /**
     * Signer asserts that the key is not only valid but also trustworthy at
     * the specified level.  Level 0 has the same meaning as an ordinary
     * validity signature.  Level 1 means that the signed key is asserted to
     * be a valid trusted introducer, with the 2nd octet of the body
     * specifying the degree of trust.  Level 2 means that the signed key is
     * asserted to be trusted to issue level 1 trust signatures, i.e., that
     * it is a "meta introducer".  Generally, a level n trust signature
     * asserts that a key is trusted to issue level n-1 trust signatures.
     * The trust amount is in a range from 0-255, interpreted such that
     * values less than 120 indicate partial trust and values of 120 or
     * greater indicate complete trust.  Implementations SHOULD emit values
     * of 60 for partial trust and 120 for complete trust.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.13">Trust Signature</a>
     */
    trustSignature(TRUST_SIG),

    /**
     * Used in conjunction with trust Signature packets (of level greater 0) to
     * limit the scope of trust that is extended.  Only signatures by the
     * target key on User IDs that match the regular expression in the body
     * of this packet have trust extended by the trust Signature subpacket.
     * The regular expression uses the same syntax as the Henry Spencer's
     * "almost public domain" regular expression [REGEX] package.  A
     * description of the syntax is found in Section 8 below.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.14">Regular Expression</a>
     */
    regularExpression(REG_EXP),

    /**
     * Signature's revocability status.  The packet body contains a Boolean
     * flag indicating whether the signature is revocable.  Signatures that
     * are not revocable have any later revocation signatures ignored.  They
     * represent a commitment by the signer that he cannot revoke his
     * signature for the life of his key.  If this packet is not present,
     * the signature is revocable.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.12">Revocable</a>
     */
    revocable(REVOCABLE),

    /**
     * The validity period of the key.  This is the number of seconds after
     * the key creation time that the key expires.  If this is not present
     * or has a value of zero, the key never expires.  This is found only on
     * a self-signature.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.6">Key Expiration Time</a>
     */
    keyExpirationTime(KEY_EXPIRE_TIME),

    /**
     * Placeholder for backwards compatibility.
     */
    placeholder(PLACEHOLDER),

    /**
     *  Symmetric algorithm numbers that indicate which algorithms the key
     *  holder prefers to use.  The subpacket body is an ordered list of
     *  octets with the most preferred listed first.  It is assumed that only
     *  algorithms listed are supported by the recipient's software.
     *  This is only found on a self-signature.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.7">Preferred Symmetric Algorithms</a>
     */
    preferredSymmetricAlgorithms(PREFERRED_SYM_ALGS),

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
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.15">Revocation Key</a>
     */
    revocationKey(REVOCATION_KEY),

    /**
     * The OpenPGP Key ID of the key issuing the signature.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.5">Issuer Key ID</a>
     */
    issuerKeyId(ISSUER_KEY_ID),

    /**
     * This subpacket describes a "notation" on the signature that the
     * issuer wishes to make.  The notation has a name and a value, each of
     * which are strings of octets.  There may be more than one notation in
     * a signature.  Notations can be used for any extension the issuer of
     * the signature cares to make.  The "flags" field holds four octets of
     * flags.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.16">Notation Data</a>
     */
    notationData(NOTATION_DATA),

    /**
     * Message digest algorithm numbers that indicate which algorithms the
     * key holder prefers to receive.  Like the preferred symmetric
     * algorithms, the list is ordered.
     * This is only found on a self-signature.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.8">Preferred Hash Algorithms</a>
     */
    preferredHashAlgorithms(PREFERRED_HASH_ALGS),

    /**
     * Compression algorithm numbers that indicate which algorithms the key
     * holder prefers to use.  Like the preferred symmetric algorithms, the
     * list is ordered. If this subpacket is not included, ZIP is preferred.
     * A zero denotes that uncompressed data is preferred; the key holder's
     * software might have no compression software in that implementation.
     * This is only found on a self-signature.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.9">Preferred Compressio Algorithms</a>
     */
    preferredCompressionAlgorithms(PREFERRED_COMP_ALGS),

    /**
     * This is a list of one-bit flags that indicate preferences that the
     * key holder has about how the key is handled on a key server.  All
     * undefined flags MUST be zero.
     * This is found only on a self-signature.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.17">Key Server Preferences</a>
     */
    keyServerPreferences(KEY_SERVER_PREFS),

    /**
     * This is a URI of a key server that the key holder prefers be used for
     * updates.  Note that keys with multiple User IDs can have a preferred
     * key server for each User ID.  Note also that since this is a URI, the
     * key server can actually be a copy of the key retrieved by ftp, http,
     * finger, etc.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.18">Preferred Key Server</a>
     */
    preferredKeyServers(PREFERRED_KEY_SERV),

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
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.19">Primary User-ID</a>
     */
    primaryUserId(PRIMARY_USER_ID),

    /**
     * This subpacket contains a URI of a document that describes the policy
     * under which the signature was issued.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.20">Policy URL</a>
     */
    policyUrl(POLICY_URL),

    /**
     * This subpacket contains a list of binary flags that hold information
     * about a key.  It is a string of octets, and an implementation MUST
     * NOT assume a fixed size.  This is so it can grow over time.  If a
     * list is shorter than an implementation expects, the unstated flags
     * are considered to be zero.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.21">Key Flags</a>
     */
    keyFlags(KEY_FLAGS),

    /**
     * This subpacket allows a keyholder to state which User ID is
     * responsible for the signing.  Many keyholders use a single key for
     * different purposes, such as business communications as well as
     * personal communications.  This subpacket allows such a keyholder to
     * state which of their roles is making a signature.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.22">Signer's User ID</a>
     */
    signerUserId(SIGNER_USER_ID),

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
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.23">Reason for Revocation</a>
     */
    revocationReason(REVOCATION_REASON),

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
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.24">Features</a>
     */
    features(FEATURES),

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
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.25">Signature Target</a>
     */
    signatureTarget(SIGNATURE_TARGET),

    /**
     * This subpacket contains a complete Signature packet body as
     * specified in Section 5.2 above.  It is useful when one signature
     * needs to refer to, or be incorporated in, another signature.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.2.3.26">Embedded Signature</a>
     */
    embeddedSignature(EMBEDDED_SIGNATURE),

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
     * @see <a href="https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.28">Issuer Fingerprint</a>
     */
    issuerFingerprint(ISSUER_FINGERPRINT),

    /**
     * AEAD algorithm numbers that indicate which AEAD algorithms the key
     * holder prefers to use.  The subpacket body is an ordered list of
     * octets with the most preferred listed first.  It is assumed that only
     * algorithms listed are supported by the recipient's software.
     * This is only found on a self-signature.
     * Note that support for the AEAD Encrypted Data packet in the general
     * is indicated by a Feature Flag.
     *
     * @see <a href="https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.8">Preferred AEAD Algorithms</a>
     */
    preferredAEADAlgorithms(PREFERRED_AEAD_ALGORITHMS),

    /**
     * The OpenPGP Key fingerprint of the intended recipient primary key.
     * If one or more subpackets of this type are included in a signature,
     * it SHOULD be considered valid only in an encrypted context, where the
     * key it was encrypted to is one of the indicated primary keys, or one
     * of their subkeys.  This can be used to prevent forwarding a signature
     * outside of its intended, encrypted context.
     *
     * Note that the length N of the fingerprint for a version 4 key is 20
     * octets; for a version 5 key N is 32.
     *
     * @see <a href="https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.29">Intended Recipient Fingerprint</a>
     */
    intendedRecipientFingerprint(INTENDED_RECIPIENT_FINGERPRINT),

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
     * @see <a href="https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10#section-5.2.3.30">Attested Certification</a>
     */
    attestedCertification(ATTESTED_CERTIFICATIONS)
    ;

    private static final Map<Integer, SignatureSubpacket> MAP = new ConcurrentHashMap<>();
    static {
        for (SignatureSubpacket p : values()) {
            MAP.put(p.code, p);
        }
    }

    private final int code;

    SignatureSubpacket(int code) {
        this.code = code;
    }

    /**
     * Return the numerical identifier of the {@link SignatureSubpacket}.
     * @return id
     */
    public int getCode() {
        return code;
    }

    /**
     * Return the {@link SignatureSubpacket} that corresponds to the provided id.
     *
     * @param code id
     * @return signature subpacket
     */
    public static SignatureSubpacket fromCode(int code) {
        SignatureSubpacket tag = MAP.get(code);
        if (tag == null) {
            throw new IllegalArgumentException("No SignatureSubpacket tag found with code " + code);
        }
        return tag;
    }

    /**
     * Convert an array of signature subpacket tags into a list of {@link SignatureSubpacket SignatureSubpackets}.
     *
     * @param codes array of codes
     * @return list of subpackets
     */
    public static List<SignatureSubpacket> fromCodes(int[] codes) {
        List<SignatureSubpacket> tags = new ArrayList<>();
        for (int code : codes) {
            tags.add(fromCode(code));
        }
        return tags;
    }
}
