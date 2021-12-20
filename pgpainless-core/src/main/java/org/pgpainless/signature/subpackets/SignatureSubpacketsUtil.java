// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.IntendedRecipientFingerprint;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.Revocable;
import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.bcpg.sig.SignatureTarget;
import org.bouncycastle.bcpg.sig.SignerUserID;
import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.util.encoders.Hex;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureSubpacket;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.signature.SignatureUtils;

/**
 * Utility class to access signature subpackets from signatures.
 *
 * Since rfc4880 is not always clear about where a signature subpacket can be located (hashed/unhashed area),
 * this class makes some educated guesses as to where the subpacket may be found when necessary.
 */
public final class SignatureSubpacketsUtil {

    private SignatureSubpacketsUtil() {

    }

    /**
     * Return the issuer-fingerprint subpacket of the signature.
     * Since this packet is self-authenticating, we expect it to be in the unhashed area,
     * however as it cannot hurt we search for it in the hashed area first.
     *
     * @param signature signature
     * @return issuer fingerprint or null
     */
    public static IssuerFingerprint getIssuerFingerprint(PGPSignature signature) {
        return hashedOrUnhashed(signature, SignatureSubpacket.issuerFingerprint);
    }

    /**
     * Return the {@link IssuerFingerprint} subpacket of the signature into a {@link org.pgpainless.key.OpenPgpFingerprint}.
     * If no v4 issuer fingerprint is present in the signature, return null.
     *
     * @param signature signature
     * @return v4 fingerprint of the issuer, or null
     */
    public static OpenPgpFingerprint getIssuerFingerprintAsOpenPgpFingerprint(PGPSignature signature) {
        IssuerFingerprint subpacket = getIssuerFingerprint(signature);
        if (subpacket == null) {
            return null;
        }

        OpenPgpFingerprint fingerprint = null;
        if (subpacket.getKeyVersion() == 4) {
            fingerprint = new OpenPgpV4Fingerprint(Hex.encode(subpacket.getFingerprint()));
        }

        return fingerprint;
    }

    /**
     * Return the issuer key-id subpacket of the signature.
     * Since this packet is self-authenticating, we expect it to be in the unhashed area,
     * however as it cannot hurt we search for it in the hashed area first.
     *
     * @param signature signature
     * @return issuer key-id or null
     */
    public static IssuerKeyID getIssuerKeyId(PGPSignature signature) {
        return hashedOrUnhashed(signature, SignatureSubpacket.issuerKeyId);
    }

    /**
     * Inspect the given signature's {@link IssuerKeyID} packet to determine the issuer key-id.
     * If no such packet is present, return null.
     *
     * @param signature signature
     * @return issuer key-id as {@link Long}
     */
    public static Long getIssuerKeyIdAsLong(PGPSignature signature) {
        IssuerKeyID keyID = getIssuerKeyId(signature);
        if (keyID == null) {
            return null;
        }
        return keyID.getKeyID();
    }

    /**
     * Return the revocation reason subpacket of the signature.
     * Since this packet is rather important for revocations, we only search for it in the
     * hashed area of the signature.
     *
     * @param signature signature
     * @return revocation reason
     */
    public static RevocationReason getRevocationReason(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.revocationReason);
    }

    /**
     * Return the signature creation time subpacket.
     * Since this packet is rather important, we only search for it in the hashed area
     * of the signature.
     *
     * @param signature signature
     * @return signature creation time subpacket
     */
    public static SignatureCreationTime getSignatureCreationTime(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.signatureCreationTime);
    }

    /**
     * Return the signature expiration time subpacket of the signature.
     * Since this packet is rather important, we only search for it in the hashed area of the signature.
     *
     * @param signature signature
     * @return signature expiration time
     */
    public static SignatureExpirationTime getSignatureExpirationTime(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.signatureExpirationTime);
    }

    /**
     * Return the signatures expiration time as a date.
     * The expiration date is computed by adding the expiration time to the signature creation date.
     * If the signature has no expiration time subpacket, or the expiration time is set to '0', this message returns null.
     *
     * @param signature signature
     * @return expiration time as date
     */
    public static Date getSignatureExpirationTimeAsDate(PGPSignature signature) {
        SignatureExpirationTime subpacket = getSignatureExpirationTime(signature);
        if (subpacket == null) {
            return null;
        }
        return SignatureUtils.datePlusSeconds(signature.getCreationTime(), subpacket.getTime());
    }

    /**
     * Return the key expiration time subpacket of this signature.
     * We only look for it in the hashed area of the signature.
     *
     * @param signature signature
     * @return key expiration time
     */
    public static KeyExpirationTime getKeyExpirationTime(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.keyExpirationTime);
    }

    /**
     * Return the signatures key-expiration time as a date.
     * The expiration date is computed by adding the signatures' key-expiration time to the signing keys
     * creation date.
     * If the signature does not have a key-expiration time subpacket, or its value is '0', this method returns null.
     *
     * @param signature self-signature carrying the key-expiration time subpacket
     * @param signingKey signature creation key
     * @return key expiration time as date
     */
    public static Date getKeyExpirationTimeAsDate(PGPSignature signature, PGPPublicKey signingKey) {
        if (signature.getKeyID() != signingKey.getKeyID()) {
            throw new IllegalArgumentException("Provided key (" + Long.toHexString(signingKey.getKeyID()) + ") did not create the signature (" + Long.toHexString(signature.getKeyID()) + ")");
        }
        KeyExpirationTime subpacket = getKeyExpirationTime(signature);
        if (subpacket == null) {
            return null;
        }

        return SignatureUtils.datePlusSeconds(signingKey.getCreationTime(), subpacket.getTime());
    }

    /**
     * Calculate the duration in seconds until the key expires after creation.
     *
     * @param expirationDate new expiration date
     * @param creationDate key creation time
     * @return life time of the key in seconds
     */
    public static long getKeyLifetimeInSeconds(@Nullable Date expirationDate, @Nonnull Date creationDate) {
        long secondsToExpire = 0; // 0 means "no expiration"
        if (expirationDate != null) {
            if (creationDate.after(expirationDate)) {
                throw new IllegalArgumentException("Key MUST NOT expire before being created. " +
                        "(creation: " + creationDate + ", expiration: " + expirationDate + ")");
            }
            secondsToExpire = (expirationDate.getTime() - creationDate.getTime()) / 1000;
        }
        return secondsToExpire;
    }

    /**
     * Return the revocable subpacket of this signature.
     * We only look for it in the hashed area of the signature.
     *
     * @param signature signature
     * @return revocable subpacket
     */
    public static Revocable getRevocable(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.revocable);
    }

    /**
     * Return the symmetric algorithm preferences from the signatures hashed area.
     *
     * @param signature signature
     * @return symm. algo. prefs
     */
    public static PreferredAlgorithms getPreferredSymmetricAlgorithms(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.preferredSymmetricAlgorithms);
    }

    /**
     * Return the preferred {@link SymmetricKeyAlgorithm SymmetricKeyAlgorithms} as present in the signature.
     * If no preference is given with regard to symmetric encryption algorithms, return an empty set.
     *
     * In any case, the resulting set is ordered by occurrence ({@link LinkedHashSet}).
     * @param signature signature
     * @return ordered set of symmetric key algorithm preferences
     */
    public static Set<SymmetricKeyAlgorithm> parsePreferredSymmetricKeyAlgorithms(PGPSignature signature) {
        Set<SymmetricKeyAlgorithm> algorithms = new LinkedHashSet<>();
        PreferredAlgorithms preferences = getPreferredSymmetricAlgorithms(signature);
        if (preferences != null) {
            for (int code : preferences.getPreferences()) {
                algorithms.add(SymmetricKeyAlgorithm.fromId(code));
            }
        }
        return algorithms;
    }

    /**
     * Return the hash algorithm preferences from the signatures hashed area.
     *
     * @param signature signature
     * @return hash algo prefs
     */
    public static PreferredAlgorithms getPreferredHashAlgorithms(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.preferredHashAlgorithms);
    }

    /**
     * Return the preferred {@link HashAlgorithm HashAlgorithms} as present in the signature.
     * If no preference is given with regard to hash algorithms, return an empty set.
     *
     * In any case, the resulting set is ordered by occurrence ({@link LinkedHashSet}).
     * @param signature signature
     * @return ordered set of hash algorithm preferences
     */
    public static Set<HashAlgorithm> parsePreferredHashAlgorithms(PGPSignature signature) {
        Set<HashAlgorithm> algorithms = new LinkedHashSet<>();
        PreferredAlgorithms preferences = getPreferredHashAlgorithms(signature);
        if (preferences != null) {
            for (int code : preferences.getPreferences()) {
                algorithms.add(HashAlgorithm.fromId(code));
            }
        }
        return algorithms;
    }

    /**
     * Return the compression algorithm preferences from the signatures hashed area.
     *
     * @param signature signature
     * @return compression algo prefs
     */
    public static PreferredAlgorithms getPreferredCompressionAlgorithms(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.preferredCompressionAlgorithms);
    }

    /**
     * Return the preferred {@link CompressionAlgorithm CompressionAlgorithms} as present in the signature.
     * If no preference is given with regard to compression algorithms, return an empty set.
     *
     * In any case, the resulting set is ordered by occurrence ({@link LinkedHashSet}).
     * @param signature signature
     * @return ordered set of compression algorithm preferences
     */
    public static Set<CompressionAlgorithm> parsePreferredCompressionAlgorithms(PGPSignature signature) {
        Set<CompressionAlgorithm> algorithms = new LinkedHashSet<>();
        PreferredAlgorithms preferences = getPreferredCompressionAlgorithms(signature);
        if (preferences != null) {
            for (int code : preferences.getPreferences()) {
                algorithms.add(CompressionAlgorithm.fromId(code));
            }
        }
        return algorithms;
    }

    /**
     * Return the primary user-id subpacket from the signatures hashed area.
     *
     * @param signature signature
     * @return primary user id
     */
    public static PrimaryUserID getPrimaryUserId(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.primaryUserId);
    }

    /**
     * Return the key flags subpacket from the signatures hashed area.
     *
     * @param signature signature
     * @return key flags
     */
    public static KeyFlags getKeyFlags(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.keyFlags);
    }

    /**
     * Return a list of key flags carried by the signature.
     * If the signature is null, or has no {@link KeyFlags} subpacket, return null.
     *
     * @param signature signature
     * @return list of key flags
     */
    public static List<KeyFlag> parseKeyFlags(@Nullable PGPSignature signature) {
        if (signature == null) {
            return null;
        }
        KeyFlags keyFlags = getKeyFlags(signature);
        if (keyFlags == null) {
            return null;
        }
        return KeyFlag.fromBitmask(keyFlags.getFlags());
    }

    /**
     * Return the features subpacket from the signatures hashed area.
     *
     * @param signature signature
     * @return features subpacket
     */
    public static Features getFeatures(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.features);
    }

    /**
     * Parse out the features subpacket of a signature.
     * If the signature has no features subpacket, return null.
     * Otherwise, return the features as a feature set.
     *
     * @param signature signature
     * @return features as set
     */
    public static @Nullable Set<Feature> parseFeatures(PGPSignature signature) {
        Features features = getFeatures(signature);
        if (features == null) {
            return null;
        }
        return new LinkedHashSet<>(Feature.fromBitmask(features.getData()[0]));
    }

    /**
     * Return the signature target subpacket from the signature.
     * We search for this subpacket in the hashed and unhashed area (in this order).
     *
     * @param signature signature
     * @return signature target
     */
    public static SignatureTarget getSignatureTarget(PGPSignature signature) {
        return hashedOrUnhashed(signature, SignatureSubpacket.signatureTarget);
    }

    /**
     * Return the notation data subpackets from the signatures hashed area.
     *
     * @param signature signature
     * @return hashed notations
     */
    public static List<NotationData> getHashedNotationData(PGPSignature signature) {
        NotationData[] notations = signature.getHashedSubPackets().getNotationDataOccurrences();
        return Arrays.asList(notations);
    }

    /**
     * Return a list of all {@link NotationData} objects from the hashed area of the signature that have a
     * notation name equal to the given notationName argument.
     *
     * @param signature signature
     * @param notationName notation name
     * @return list of matching notation data objects
     */
    public static List<NotationData> getHashedNotationData(PGPSignature signature, String notationName) {
        List<NotationData> allNotations = getHashedNotationData(signature);
        List<NotationData> withName = new ArrayList<>();
        for (NotationData data : allNotations) {
            if (data.getNotationName().equals(notationName)) {
                withName.add(data);
            }
        }
        return withName;
    }

    /**
     * Return the notation data subpackets from the signatures unhashed area.
     *
     * @param signature signture
     * @return unhashed notations
     */
    public static List<NotationData> getUnhashedNotationData(PGPSignature signature) {
        NotationData[] notations = signature.getUnhashedSubPackets().getNotationDataOccurrences();
        return Arrays.asList(notations);
    }

    /**
     * Return a list of all {@link NotationData} objects from the unhashed area of the signature that have a
     * notation name equal to the given notationName argument.
     *
     * @param signature signature
     * @param notationName notation name
     * @return list of matching notation data objects
     */
    public static List<NotationData> getUnhashedNotationData(PGPSignature signature, String notationName) {
        List<NotationData> allNotations = getUnhashedNotationData(signature);
        List<NotationData> withName = new ArrayList<>();
        for (NotationData data : allNotations) {
            if (data.getNotationName().equals(notationName)) {
                withName.add(data);
            }
        }
        return withName;
    }

    /**
     * Return the revocation key subpacket from the signatures hashed area.
     *
     * @param signature signature
     * @return revocation key
     */
    public static RevocationKey getRevocationKey(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.revocationKey);
    }

    /**
     * Return the signers user-id from the hashed area of the signature.
     * TODO: Can this subpacket also be found in the unhashed area?
     *
     * @param signature signature
     * @return signers user-id
     */
    public static SignerUserID getSignerUserID(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.signerUserId);
    }

    /**
     * Return the intended recipients fingerprint subpackets from the hashed area of this signature.
     *
     * @param signature signature
     * @return intended recipient fingerprint subpackets
     */
    public static List<IntendedRecipientFingerprint> getIntendedRecipientFingerprints(PGPSignature signature) {
        org.bouncycastle.bcpg.SignatureSubpacket[] subpackets = signature.getHashedSubPackets().getSubpackets(SignatureSubpacket.intendedRecipientFingerprint.getCode());
        List<IntendedRecipientFingerprint> intendedRecipients = new ArrayList<>(subpackets.length);
        for (org.bouncycastle.bcpg.SignatureSubpacket subpacket : subpackets) {
            intendedRecipients.add((IntendedRecipientFingerprint) subpacket);
        }
        return intendedRecipients;
    }

    /**
     * Return the embedded signature subpacket from the signatures hashed area.
     *
     * @param signature signature
     * @return embedded signature
     */
    public static PGPSignatureList getEmbeddedSignature(PGPSignature signature) throws PGPException {
        PGPSignatureList hashed = signature.getHashedSubPackets().getEmbeddedSignatures();
        if (!hashed.isEmpty()) {
            return hashed;
        }
        return signature.getUnhashedSubPackets().getEmbeddedSignatures();
    }

    /**
     * Return the signatures exportable certification subpacket from the hashed area.
     *
     * @param signature signature
     * @return exportable certification subpacket
     */
    public static Exportable getExportableCertification(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.exportableCertification);
    }

    /**
     * Return the trust signature packet from the signatures hashed area.
     *
     * @param signature signature
     * @return trust signature subpacket
     */
    public static TrustSignature getTrustSignature(PGPSignature signature) {
        return hashed(signature, SignatureSubpacket.trustSignature);
    }

    /**
     * Select a list of all signature subpackets of the given type, which are present in the hashed area of
     * the given signature.
     *
     * @param signature signature
     * @param type subpacket type
     * @param <P> generic subpacket type
     * @return list of subpackets from the hashed area
     */
    private static <P extends org.bouncycastle.bcpg.SignatureSubpacket> P hashed(PGPSignature signature, SignatureSubpacket type) {
        return getSignatureSubpacket(signature.getHashedSubPackets(), type);
    }

    /**
     * Select a list of all signature subpackets of the given type, which are present in the unhashed area of
     * the given signature.
     *
     * @param signature signature
     * @param type subpacket type
     * @param <P> generic subpacket type
     * @return list of subpackets from the unhashed area
     */
    private static <P extends org.bouncycastle.bcpg.SignatureSubpacket> P unhashed(PGPSignature signature, SignatureSubpacket type) {
        return getSignatureSubpacket(signature.getUnhashedSubPackets(), type);
    }

    /**
     * Select a list of all signature subpackets of the given type, which are present in either the hashed
     * or the unhashed area of the given signature.
     *
     * @param signature signature
     * @param type subpacket type
     * @param <P> generic subpacket type
     * @return list of subpackets from the hashed/unhashed area
     */
    private static <P extends org.bouncycastle.bcpg.SignatureSubpacket> P hashedOrUnhashed(PGPSignature signature, SignatureSubpacket type) {
        P hashedSubpacket = hashed(signature, type);
        return hashedSubpacket != null ? hashedSubpacket : unhashed(signature, type);
    }

    /**
     * Return the last occurence of a subpacket type in the given signature subpacket vector.
     *
     * @param vector subpacket vector (hashed/unhashed)
     * @param type subpacket type
     * @param <P> generic return type of the subpacket
     * @return last occurrence of the subpacket in the vector
     */
    public static <P extends org.bouncycastle.bcpg.SignatureSubpacket> P getSignatureSubpacket(PGPSignatureSubpacketVector vector, SignatureSubpacket type) {
        org.bouncycastle.bcpg.SignatureSubpacket[] allPackets = vector.getSubpackets(type.getCode());
        if (allPackets.length == 0) {
            return null;
        }
        return (P) allPackets[allPackets.length - 1]; // return last
    }

    /**
     * Make sure that the given key type can carry the given key flags.
     *
     * @param type key type
     * @param flags key flags
     */
    public static void assureKeyCanCarryFlags(KeyType type, KeyFlag... flags) {
        final int mask = KeyFlag.toBitmask(flags);

        if (!type.canCertify() && KeyFlag.hasKeyFlag(mask, KeyFlag.CERTIFY_OTHER)) {
            throw new IllegalArgumentException("KeyType " + type.getName() + " cannot carry key flag CERTIFY_OTHER.");
        }

        if (!type.canSign() && KeyFlag.hasKeyFlag(mask, KeyFlag.SIGN_DATA)) {
            throw new IllegalArgumentException("KeyType " + type.getName() + " cannot carry key flag SIGN_DATA.");
        }

        if (!type.canEncryptCommunication() && KeyFlag.hasKeyFlag(mask, KeyFlag.ENCRYPT_COMMS)) {
            throw new IllegalArgumentException("KeyType " + type.getName() + " cannot carry key flag ENCRYPT_COMMS.");
        }

        if (!type.canEncryptStorage() && KeyFlag.hasKeyFlag(mask, KeyFlag.ENCRYPT_STORAGE)) {
            throw new IllegalArgumentException("KeyType " + type.getName() + " cannot carry key flag ENCRYPT_STORAGE.");
        }

        if (!type.canAuthenticate() && KeyFlag.hasKeyFlag(mask, KeyFlag.AUTHENTICATION)) {
            throw new IllegalArgumentException("KeyType " + type.getName() + " cannot carry key flag AUTHENTICATION.");
        }
    }

    public static void assureKeyCanCarryFlags(PublicKeyAlgorithm algorithm, KeyFlag... flags) {
        final int mask = KeyFlag.toBitmask(flags);

        if (!algorithm.isSigningCapable() && KeyFlag.hasKeyFlag(mask, KeyFlag.CERTIFY_OTHER)) {
            throw new IllegalArgumentException("Algorithm " + algorithm + " cannot be used with key flag CERTIFY_OTHER.");
        }

        if (!algorithm.isSigningCapable() && KeyFlag.hasKeyFlag(mask, KeyFlag.SIGN_DATA)) {
            throw new IllegalArgumentException("Algorithm " + algorithm + " cannot be used with key flag SIGN_DATA.");
        }

        if (!algorithm.isEncryptionCapable() && KeyFlag.hasKeyFlag(mask, KeyFlag.ENCRYPT_COMMS)) {
            throw new IllegalArgumentException("Algorithm " + algorithm + " cannot be used with key flag ENCRYPT_COMMS.");
        }

        if (!algorithm.isEncryptionCapable() && KeyFlag.hasKeyFlag(mask, KeyFlag.ENCRYPT_STORAGE)) {
            throw new IllegalArgumentException("Algorithm " + algorithm + " cannot be used with key flag ENCRYPT_STORAGE.");
        }

        if (!algorithm.isSigningCapable() && KeyFlag.hasKeyFlag(mask, KeyFlag.AUTHENTICATION)) {
            throw new IllegalArgumentException("Algorithm " + algorithm + " cannot be used with key flag AUTHENTICATION.");
        }
    }
}
