// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer;

import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureSubpacket;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.pgpainless.util.DateUtil;
import org.pgpainless.util.NotationRegistry;

/**
 * A collection of validators that perform validation steps over signatures.
 */
public abstract class SignatureValidator {

    public abstract void verify(PGPSignature signature) throws SignatureValidationException;

    /**
     * Check, whether there is the possibility that the given signature was created by the given key.
     * {@link #verify(PGPSignature)} throws a {@link SignatureValidationException} if we can say with certainty that
     * the signature was not created by the given key (e.g. if the sig carries another issuer, issuer fingerprint packet).
     *
     * If there is no information found in the signature about who created it (no issuer, no fingerprint),
     * {@link #verify(PGPSignature)} will simply return since it is plausible that the given key created the sig.
     *
     * @param signingKey signing key
     * @return validator that throws a {@link SignatureValidationException} if the signature was not possibly made by
     * the given key.
     */
    public static SignatureValidator wasPossiblyMadeByKey(PGPPublicKey signingKey) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                OpenPgpFingerprint signingKeyFingerprint = OpenPgpFingerprint.of(signingKey);

                Long issuer = SignatureSubpacketsUtil.getIssuerKeyIdAsLong(signature);
                if (issuer != null) {
                    if (issuer != signingKey.getKeyID()) {
                        throw new SignatureValidationException("Signature was not created by " +
                                signingKeyFingerprint + " (signature issuer: " + Long.toHexString(issuer) + ")");
                    }
                }

                OpenPgpFingerprint fingerprint =
                        SignatureSubpacketsUtil.getIssuerFingerprintAsOpenPgpFingerprint(signature);
                if (fingerprint != null) {
                    if (!fingerprint.equals(signingKeyFingerprint)) {
                        throw new SignatureValidationException("Signature was not created by " +
                                signingKeyFingerprint + " (signature fingerprint: " + fingerprint + ")");
                    }
                }

                // No issuer information found, so we cannot rule out that we did not create the sig
            }
        };

    }

    /**
     * Verify that a subkey binding signature - if the subkey is signing-capable - contains a valid primary key
     * binding signature.
     *
     * @param primaryKey primary key
     * @param subkey subkey
     * @param policy policy
     * @param referenceDate reference date for signature verification
     * @return validator
     */
    public static SignatureValidator hasValidPrimaryKeyBindingSignatureIfRequired(PGPPublicKey primaryKey,
                                                                                  PGPPublicKey subkey, Policy policy,
                                                                                  Date referenceDate) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                if (!PublicKeyAlgorithm.requireFromId(signature.getKeyAlgorithm()).isSigningCapable()) {
                    // subkey is not signing capable -> No need to process embedded sigs
                    return;
                }

                KeyFlags keyFlags = SignatureSubpacketsUtil.getKeyFlags(signature);
                if (keyFlags == null) {
                    return;
                }
                if (!KeyFlag.hasKeyFlag(keyFlags.getFlags(), KeyFlag.SIGN_DATA)
                        && !KeyFlag.hasKeyFlag(keyFlags.getFlags(), KeyFlag.CERTIFY_OTHER)) {
                    return;
                }

                try {
                    PGPSignatureList embeddedSignatures = SignatureSubpacketsUtil.getEmbeddedSignature(signature);
                    boolean hasValidPrimaryKeyBinding = false;
                    Map<PGPSignature, Exception> rejectedEmbeddedSigs = new ConcurrentHashMap<>();
                    for (PGPSignature embedded : embeddedSignatures) {

                        if (SignatureType.valueOf(embedded.getSignatureType()) == SignatureType.PRIMARYKEY_BINDING) {

                            try {
                                signatureStructureIsAcceptable(subkey, policy).verify(embedded);
                                signatureIsEffective(referenceDate).verify(embedded);
                                correctPrimaryKeyBindingSignature(primaryKey, subkey).verify(embedded);

                                hasValidPrimaryKeyBinding = true;
                                break;
                            } catch (SignatureValidationException e) {
                                rejectedEmbeddedSigs.put(embedded, e);
                            }
                        }
                    }

                    if (!hasValidPrimaryKeyBinding) {
                        throw new SignatureValidationException(
                                "Missing primary key binding signature on signing capable subkey " +
                                        Long.toHexString(subkey.getKeyID()), rejectedEmbeddedSigs);
                    }
                } catch (PGPException e) {
                    throw new SignatureValidationException("Cannot process list of embedded signatures.", e);
                }
            }
        };
    }

    /**
     * Verify that a signature has an acceptable structure.
     *
     * @param signingKey signing key
     * @param policy policy
     * @return validator
     */
    public static SignatureValidator signatureStructureIsAcceptable(PGPPublicKey signingKey, Policy policy) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                signatureIsNotMalformed(signingKey).verify(signature);
                if (signature.getVersion() >= 4) {
                    signatureDoesNotHaveCriticalUnknownNotations(policy.getNotationRegistry()).verify(signature);
                    signatureDoesNotHaveCriticalUnknownSubpackets().verify(signature);
                }
                signatureUsesAcceptableHashAlgorithm(policy).verify(signature);
                signatureUsesAcceptablePublicKeyAlgorithm(policy, signingKey).verify(signature);
            }
        };
    }

    /**
     * Verify that a signature was made using an acceptable {@link PublicKeyAlgorithm}.
     *
     * @param policy policy
     * @param signingKey signing key
     * @return validator
     */
    private static SignatureValidator signatureUsesAcceptablePublicKeyAlgorithm(Policy policy,
                                                                                PGPPublicKey signingKey) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                PublicKeyAlgorithm algorithm = PublicKeyAlgorithm.requireFromId(signingKey.getAlgorithm());
                    int bitStrength = signingKey.getBitStrength();
                    if (bitStrength == -1) {
                        throw new SignatureValidationException("Cannot determine bit strength of signing key.");
                    }
                    if (!policy.getPublicKeyAlgorithmPolicy().isAcceptable(algorithm, bitStrength)) {
                        throw new SignatureValidationException("Signature was made using unacceptable key. " +
                                algorithm + " (" + bitStrength +
                                " bits) is not acceptable according to the public key algorithm policy.");
                    }
            }
        };
    }

    /**
     * Verify that a signature uses an acceptable {@link HashAlgorithm}.
     *
     * @param policy policy
     * @return validator
     */
    private static SignatureValidator signatureUsesAcceptableHashAlgorithm(Policy policy) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                try {
                    HashAlgorithm hashAlgorithm = HashAlgorithm.requireFromId(signature.getHashAlgorithm());
                    Policy.HashAlgorithmPolicy hashAlgorithmPolicy =
                            getHashAlgorithmPolicyForSignature(signature, policy);
                    if (!hashAlgorithmPolicy.isAcceptable(signature.getHashAlgorithm(), signature.getCreationTime())) {
                        throw new SignatureValidationException("Signature uses unacceptable hash algorithm " +
                                hashAlgorithm + " (Signature creation time: " +
                                DateUtil.formatUTCDate(signature.getCreationTime()) + ")");
                    }
                } catch (NoSuchElementException e) {
                    throw new SignatureValidationException("Signature uses unknown hash algorithm " +
                            signature.getHashAlgorithm());
                }
            }
        };
    }

    /**
     * Return the applicable {@link Policy.HashAlgorithmPolicy} for the given {@link PGPSignature}.
     * Revocation signatures are being policed using a different policy than non-revocation signatures.
     *
     * @param signature signature
     * @param policy revocation policy for revocation sigs, normal policy for non-rev sigs
     * @return policy
     */
    private static Policy.HashAlgorithmPolicy getHashAlgorithmPolicyForSignature(PGPSignature signature,
                                                                                 Policy policy) {
        SignatureType type = SignatureType.valueOf(signature.getSignatureType());
        Policy.HashAlgorithmPolicy hashAlgorithmPolicy;
        if (type == SignatureType.CERTIFICATION_REVOCATION || type == SignatureType.KEY_REVOCATION ||
                type == SignatureType.SUBKEY_REVOCATION) {
            hashAlgorithmPolicy = policy.getRevocationSignatureHashAlgorithmPolicy();
        } else {
            hashAlgorithmPolicy = policy.getSignatureHashAlgorithmPolicy();
        }
        return hashAlgorithmPolicy;
    }

    /**
     * Verify that a signature does not carry critical unknown notations.
     *
     * @param registry notation registry of known notations
     * @return validator
     */
    public static SignatureValidator signatureDoesNotHaveCriticalUnknownNotations(NotationRegistry registry) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                List<NotationData> hashedNotations = SignatureSubpacketsUtil.getHashedNotationData(signature);
                for (NotationData notation : hashedNotations) {
                    if (!notation.isCritical()) {
                        continue;
                    }
                    if (!registry.isKnownNotation(notation.getNotationName())) {
                        throw new SignatureValidationException("Signature contains unknown critical notation '" +
                                notation.getNotationName() + "' in its hashed area.");
                    }
                }
            }
        };
    }

    /**
     * Verify that a signature does not contain critical unknown subpackets.
     *
     * @return validator
     */
    public static SignatureValidator signatureDoesNotHaveCriticalUnknownSubpackets() {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                PGPSignatureSubpacketVector hashedSubpackets = signature.getHashedSubPackets();
                for (int criticalTag : hashedSubpackets.getCriticalTags()) {
                    try {
                        SignatureSubpacket.requireFromCode(criticalTag);
                    } catch (NoSuchElementException e) {
                        throw new SignatureValidationException(
                                "Signature contains unknown critical subpacket of type " +
                                        Long.toHexString(criticalTag));
                    }
                }
            }
        };
    }

    /**
     * Verify that a signature is effective right now.
     *
     * @return validator
     */
    public static SignatureValidator signatureIsEffective() {
        return signatureIsEffective(new Date());
    }

    /**
     * Verify that a signature is effective at the given reference date.
     *
     * @param referenceDate reference date for signature verification
     * @return validator
     */
    public static SignatureValidator signatureIsEffective(Date referenceDate) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                signatureIsAlreadyEffective(referenceDate).verify(signature);
                signatureIsNotYetExpired(referenceDate).verify(signature);
            }
        };
    }

    /**
     * Verify that a signature was created prior to the given reference date.
     *
     * @param referenceDate reference date for signature verification
     * @return validator
     */
    public static SignatureValidator signatureIsAlreadyEffective(Date referenceDate) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                Date signatureCreationTime = SignatureSubpacketsUtil.getSignatureCreationTime(signature).getTime();
                // Hard revocations are always effective
                if (SignatureUtils.isHardRevocation(signature)) {
                    return;
                }

                if (signatureCreationTime.after(referenceDate)) {
                    throw new SignatureValidationException("Signature was created at " + signatureCreationTime +
                            " and is therefore not yet valid at " + referenceDate);
                }
            }
        };
    }

    /**
     * Verify that a signature is not yet expired.
     *
     * @param referenceDate reference date for signature verification
     * @return validator
     */
    public static SignatureValidator signatureIsNotYetExpired(Date referenceDate) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                // Hard revocations do not expire
                if (SignatureUtils.isHardRevocation(signature)) {
                    return;
                }

                Date signatureExpirationTime = SignatureSubpacketsUtil.getSignatureExpirationTimeAsDate(signature);
                if (signatureExpirationTime != null && signatureExpirationTime.before(referenceDate)) {
                    throw new SignatureValidationException("Signature is already expired (expiration: " +
                            signatureExpirationTime + ", validation: " + referenceDate + ")");
                }
            }
        };
    }

    /**
     * Verify that a signature is not malformed.
     * A signature is malformed if it has no hashed creation time subpacket,
     * it predates the creation time of the signing key, or it predates the creation date
     * of the signing key binding signature.
     *
     * @param creator signing key
     * @return validator
     */
    public static SignatureValidator signatureIsNotMalformed(PGPPublicKey creator) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                if (signature.getVersion() >= 4) {
                    signatureHasHashedCreationTime().verify(signature);
                }
                signatureDoesNotPredateSigningKey(creator).verify(signature);
                if (signature.getSignatureType() != SignatureType.PRIMARYKEY_BINDING.getCode()) {
                    signatureDoesNotPredateSigningKeyBindingDate(creator).verify(signature);
                }
            }
        };
    }

    public static SignatureValidator signatureDoesNotPredateSignee(PGPPublicKey signee) {
        return signatureDoesNotPredateKeyCreation(signee);
    }

    /**
     * Verify that a signature has a hashed creation time subpacket.
     *
     * @return validator
     */
    public static SignatureValidator signatureHasHashedCreationTime() {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                SignatureCreationTime creationTime = SignatureSubpacketsUtil.getSignatureCreationTime(signature);
                if (creationTime == null) {
                    throw new SignatureValidationException(
                            "Malformed signature. Signature has no signature creation time subpacket in its hashed area.");
                }
            }
        };
    }

    /**
     * Verify that a signature does not predate the creation time of the signing key.
     *
     * @param key signing key
     * @return validator
     */
    public static SignatureValidator signatureDoesNotPredateSigningKey(PGPPublicKey key) {
        return signatureDoesNotPredateKeyCreation(key);
    }

    /**
     * Verify that a signature does not predate the creation time of the given key.
     *
     * @param key key
     * @return validator
     */
    public static SignatureValidator signatureDoesNotPredateKeyCreation(PGPPublicKey key) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                Date keyCreationTime = key.getCreationTime();
                Date signatureCreationTime = signature.getCreationTime();

                if (keyCreationTime.after(signatureCreationTime)) {
                    throw new SignatureValidationException("Signature predates key (key creation: " +
                            keyCreationTime + ", signature creation: " + signatureCreationTime + ")");
                }
            }
        };
    }

    /**
     * Verify that a signature does not predate the binding date of the signing key.
     *
     * @param signingKey signing key
     * @return validator
     */
    public static SignatureValidator signatureDoesNotPredateSigningKeyBindingDate(PGPPublicKey signingKey) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                if (signingKey.isMasterKey()) {
                    return;
                }
                boolean predatesBindingSig = true;
                Iterator<PGPSignature> bindingSignatures =
                        signingKey.getSignaturesOfType(SignatureType.SUBKEY_BINDING.getCode());
                if (!bindingSignatures.hasNext()) {
                    throw new SignatureValidationException("Signing subkey does not have a subkey binding signature.");
                }
                while (bindingSignatures.hasNext()) {
                    PGPSignature bindingSig = bindingSignatures.next();
                    if (!bindingSig.getCreationTime().after(signature.getCreationTime())) {
                        predatesBindingSig = false;
                    }
                }
                if (predatesBindingSig) {
                    throw new SignatureValidationException(
                            "Signature was created before the signing key was bound to the key ring.");
                }
            }
        };
    }

    /**
     * Verify that a subkey binding signature is correct.
     *
     * @param primaryKey primary key
     * @param subkey subkey
     * @return validator
     */
    public static SignatureValidator correctSubkeyBindingSignature(PGPPublicKey primaryKey, PGPPublicKey subkey) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                if (primaryKey.getKeyID() == subkey.getKeyID()) {
                    throw new SignatureValidationException("Primary key cannot be its own subkey.");
                }
                try {
                    signature.init(ImplementationFactory.getInstance()
                            .getPGPContentVerifierBuilderProvider(), primaryKey);
                    boolean valid = signature.verifyCertification(primaryKey, subkey);
                    if (!valid) {
                        throw new SignatureValidationException("Signature is not correct.");
                    }
                } catch (PGPException | ClassCastException e) {
                    throw new SignatureValidationException("Cannot verify subkey binding signature correctness", e);
                }
            }
        };
    }

    /**
     * Verify that a primary key binding signature is correct.
     *
     * @param primaryKey primary key
     * @param subkey subkey
     * @return validator
     */
    public static SignatureValidator correctPrimaryKeyBindingSignature(PGPPublicKey primaryKey, PGPPublicKey subkey) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), subkey);
                    boolean valid = signature.verifyCertification(primaryKey, subkey);
                    if (!valid) {
                        throw new SignatureValidationException("Primary Key Binding Signature is not correct.");
                    }
                } catch (PGPException | ClassCastException e) {
                    throw new SignatureValidationException(
                            "Cannot verify primary key binding signature correctness", e);
                }
            }
        };
    }

    /**
     * Verify that a direct-key signature is correct.
     *
     * @param signer signing key
     * @param signee signed key
     * @return validator
     */
    public static SignatureValidator correctSignatureOverKey(PGPPublicKey signer, PGPPublicKey signee) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signer);
                    boolean valid;
                    if (signer.getKeyID() != signee.getKeyID()) {
                        valid = signature.verifyCertification(signer, signee);
                    } else {
                        valid = signature.verifyCertification(signee);
                    }
                    if (!valid) {
                        throw new SignatureValidationException("Signature is not correct.");
                    }
                } catch (PGPException | ClassCastException e) {
                    throw new SignatureValidationException("Cannot verify direct-key signature correctness", e);
                }
            }
        };
    }

    /**
     * Verify that a signature is a certification signature.
     *
     * @return validator
     */
    public static SignatureValidator signatureIsCertification() {
        return signatureIsOfType(
                SignatureType.POSITIVE_CERTIFICATION,
                SignatureType.CASUAL_CERTIFICATION,
                SignatureType.GENERIC_CERTIFICATION,
                SignatureType.NO_CERTIFICATION);
    }

    /**
     * Verify that a signature type equals one of the given {@link SignatureType SignatureTypes}.
     *
     * @param signatureTypes one or more signature types
     * @return validator
     */
    public static SignatureValidator signatureIsOfType(SignatureType... signatureTypes) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                SignatureType type = SignatureType.valueOf(signature.getSignatureType());
                boolean valid = false;
                for (SignatureType allowed : signatureTypes) {
                    if (type == allowed) {
                        valid = true;
                        break;
                    }
                }
                if (!valid) {
                    throw new SignatureValidationException("Signature is of type " + type + " while only " +
                            Arrays.toString(signatureTypes) + " are allowed here.");
                }
            }
        };
    }

    /**
     * Verify that a signature over a user-id is correct.
     *
     * @param userId user-id
     * @param certifiedKey key carrying the user-id
     * @param certifyingKey key that created the signature.
     * @return validator
     */
    public static SignatureValidator correctSignatureOverUserId(String userId, PGPPublicKey certifiedKey,
                                                                PGPPublicKey certifyingKey) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                try {
                    signature.init(ImplementationFactory.getInstance()
                            .getPGPContentVerifierBuilderProvider(), certifyingKey);
                    boolean valid = signature.verifyCertification(userId, certifiedKey);
                    if (!valid) {
                        throw new SignatureValidationException("Signature over user-id '" + userId +
                                "' is not correct.");
                    }
                } catch (PGPException | ClassCastException e) {
                    throw new SignatureValidationException("Cannot verify signature over user-id '" +
                            userId + "'.", e);
                }
            }
        };
    }

    /**
     * Verify that a signature over a user-attribute packet is correct.
     *
     * @param userAttributes user attributes
     * @param certifiedKey key carrying the user-attributes
     * @param certifyingKey key that created the certification signature
     * @return validator
     */
    public static SignatureValidator correctSignatureOverUserAttributes(PGPUserAttributeSubpacketVector userAttributes,
                                                                        PGPPublicKey certifiedKey,
                                                                        PGPPublicKey certifyingKey) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                try {
                    signature.init(ImplementationFactory.getInstance()
                            .getPGPContentVerifierBuilderProvider(), certifyingKey);
                    boolean valid = signature.verifyCertification(userAttributes, certifiedKey);
                    if (!valid) {
                        throw new SignatureValidationException("Signature over user-attribute vector is not correct.");
                    }
                } catch (PGPException | ClassCastException e) {
                    throw new SignatureValidationException("Cannot verify signature over user-attribute vector.", e);
                }
            }
        };
    }

    public static SignatureValidator signatureWasCreatedInBounds(Date notBefore, Date notAfter) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                Date timestamp = signature.getCreationTime();
                if (notBefore != null && timestamp.before(notBefore)) {
                    throw new SignatureValidationException(
                            "Signature was made before the earliest allowed signature creation time. Created: " +
                            DateUtil.formatUTCDate(timestamp) + " Earliest allowed: " +
                                    DateUtil.formatUTCDate(notBefore));
                }
                if (notAfter != null && timestamp.after(notAfter)) {
                    throw new SignatureValidationException(
                            "Signature was made after the latest allowed signature creation time. Created: " +
                            DateUtil.formatUTCDate(timestamp) + " Latest allowed: " +
                                    DateUtil.formatUTCDate(notAfter));
                }
            }
        };
    }

}
