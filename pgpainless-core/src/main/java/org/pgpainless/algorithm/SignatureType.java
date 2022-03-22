// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import org.bouncycastle.openpgp.PGPSignature;

import javax.annotation.Nonnull;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enum that enlists all the Signature Types defined in rfc4880 section 5.2.1
 * See {@link org.bouncycastle.openpgp.PGPSignature} for comparison.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4880#section-5.11">rfc4880 §5.2.1. Signature Types</a>
 */
public enum SignatureType {

    /**
     * Signature of a binary document.
     * This means the signer owns it, created it, or certifies that it
     * has not been modified.
     */
    BINARY_DOCUMENT(PGPSignature.BINARY_DOCUMENT),

    /**
     * Signature of a canonical text document.
     * This means the signer owns it, created it, or certifies that it
     * has not been modified.  The signature is calculated over the text
     * data with its line endings converted to {@code <CR><LF>}.
     */
    CANONICAL_TEXT_DOCUMENT(PGPSignature.CANONICAL_TEXT_DOCUMENT),

    /**
     * Standalone signature.
     * This signature is a signature of only its own subpacket contents.
     * It is calculated identically to a signature over a zero-length
     * binary document.  Note that it doesn't make sense to have a V3
     * standalone signature.
     */
    STANDALONE(PGPSignature.STAND_ALONE),

    /**
     * Generic certification of a User ID and Public-Key packet.
     * The issuer of this certification does not make any particular
     * assertion as to how well the certifier has checked that the owner
     * of the key is in fact the person described by the User ID.
     */
    GENERIC_CERTIFICATION(PGPSignature.DEFAULT_CERTIFICATION),

    /**
     * Persona certification of a User ID and Public-Key packet.
     * The issuer of this certification has not done any verification of
     * the claim that the owner of this key is the User ID specified.
     */
    NO_CERTIFICATION(PGPSignature.NO_CERTIFICATION),

    /**
     * Casual certification of a User ID and Public-Key packet.
     * The issuer of this certification has done some casual
     * verification of the claim of identity.
     */
    CASUAL_CERTIFICATION(PGPSignature.CASUAL_CERTIFICATION),

    /**
     * Positive certification of a User ID and Public-Key packet.
     * The issuer of this certification has done substantial
     * verification of the claim of identity.
     */
    POSITIVE_CERTIFICATION(PGPSignature.POSITIVE_CERTIFICATION),

    /**
     * Subkey Binding Signature.
     * This signature is a statement by the top-level signing key that
     * indicates that it owns the subkey.  This signature is calculated
     * directly on the primary key and subkey, and not on any User ID or
     * other packets.  A signature that binds a signing subkey MUST have
     * an Embedded Signature subpacket in this binding signature that
     * contains a {@link #PRIMARYKEY_BINDING} signature made by the
     * signing subkey on the primary key and subkey.
     */
    SUBKEY_BINDING(PGPSignature.SUBKEY_BINDING),

    /**
     * Primary Key Binding Signature
     * This signature is a statement by a signing subkey, indicating
     * that it is owned by the primary key and subkey.  This signature
     * is calculated the same way as a {@link #SUBKEY_BINDING} signature:
     * directly on the primary key and subkey, and not on any User ID or
     * other packets.
     */
    PRIMARYKEY_BINDING(PGPSignature.PRIMARYKEY_BINDING),

    /**
     * Signature directly on a key
     * This signature is calculated directly on a key.  It binds the
     * information in the Signature subpackets to the key, and is
     * appropriate to be used for subpackets that provide information
     * about the key, such as the Revocation Key subpacket.  It is also
     * appropriate for statements that non-self certifiers want to make
     * about the key itself, rather than the binding between a key and a
     * name.
     */
    DIRECT_KEY(PGPSignature.DIRECT_KEY),

    /**
     * Key revocation signature
     * The signature is calculated directly on the key being revoked.  A
     * revoked key is not to be used.  Only revocation signatures by the
     * key being revoked, or by an authorized revocation key, should be
     * considered valid revocation signatures.
     */
    KEY_REVOCATION(PGPSignature.KEY_REVOCATION),

    /**
     * Subkey revocation signature
     * The signature is calculated directly on the subkey being revoked.
     * A revoked subkey is not to be used.  Only revocation signatures
     * by the top-level signature key that is bound to this subkey, or
     * by an authorized revocation key, should be considered valid
     * revocation signatures.
     */
    SUBKEY_REVOCATION(PGPSignature.SUBKEY_REVOCATION),

    /**
     * Certification revocation signature
     * This signature revokes an earlier User ID certification signature
     * (signature class 0x10 through 0x13) or signature {@link #DIRECT_KEY}.
     * It should be issued by the same key that issued the
     * revoked signature or an authorized revocation key.  The signature
     * is computed over the same data as the certificate that it
     * revokes, and should have a later creation date than that
     * certificate.
     */
    CERTIFICATION_REVOCATION(PGPSignature.CERTIFICATION_REVOCATION),

    /**
     * Timestamp signature.
     * This signature is only meaningful for the timestamp contained in
     * it.
     */
    TIMESTAMP(PGPSignature.TIMESTAMP),

    /**
     * Third-Party Confirmation signature.
     * This signature is a signature over some other OpenPGP Signature
     * packet(s).  It is analogous to a notary seal on the signed data.
     * A third-party signature SHOULD include Signature Target
     * subpacket(s) to give easy identification.  Note that we really do
     * mean SHOULD.  There are plausible uses for this (such as a blind
     * party that only sees the signature, not the key or source
     * document) that cannot include a target subpacket.
     */
    THIRD_PARTY_CONFIRMATION(0x50)
    ;

    private static final Map<Integer, SignatureType> map = new ConcurrentHashMap<>();
    static {
        for (SignatureType sigType : SignatureType.values()) {
            map.put(sigType.getCode(), sigType);
        }
    }

    /**
     * Convert a numerical id into a {@link SignatureType}.
     *
     * @param code numeric id
     * @return signature type enum
     * @throws IllegalArgumentException in case of an unmatched signature type code
     */
    @Nonnull
    public static SignatureType valueOf(int code) {
        SignatureType type = map.get(code);
        if (type != null) {
            return type;
        }
        throw new IllegalArgumentException("Signature type 0x" + Integer.toHexString(code) + " appears to be invalid.");
    }

    private final int code;

    SignatureType(int code) {
        this.code = code;
    }

    /**
     * Return the numeric id of the signature type enum.
     *
     * @return numeric id
     */
    public int getCode() {
        return code;
    }

    public static boolean isRevocationSignature(int signatureType) {
        return isRevocationSignature(SignatureType.valueOf(signatureType));
    }

    public static boolean isRevocationSignature(SignatureType signatureType) {
        switch (signatureType) {
            case BINARY_DOCUMENT:
            case CANONICAL_TEXT_DOCUMENT:
            case STANDALONE:
            case GENERIC_CERTIFICATION:
            case NO_CERTIFICATION:
            case CASUAL_CERTIFICATION:
            case POSITIVE_CERTIFICATION:
            case SUBKEY_BINDING:
            case PRIMARYKEY_BINDING:
            case DIRECT_KEY:
            case TIMESTAMP:
            case THIRD_PARTY_CONFIRMATION:
                return false;
            case KEY_REVOCATION:
            case SUBKEY_REVOCATION:
            case CERTIFICATION_REVOCATION:
                return true;
            default:
                throw new IllegalArgumentException("Unknown signature type: " + signatureType);
        }
    }

}
