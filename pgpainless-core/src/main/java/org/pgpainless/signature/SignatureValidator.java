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
package org.pgpainless.signature;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureSubpacket;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.pgpainless.util.BCUtil;
import org.pgpainless.util.NotationRegistry;

public abstract class SignatureValidator {

    public abstract void verify(PGPSignature signature) throws SignatureValidationException;

    public static boolean verifyUninitializedSignature(PGPSignature signature, InputStream signedData, PGPPublicKey signingKey, Policy policy, Date validationDate) throws SignatureValidationException {
        initializeSignatureAndUpdateWithSignedData(signature, signedData, signingKey);
        return verifyInitializedSignature(signature, signingKey, policy, validationDate);
    }

    public static void initializeSignatureAndUpdateWithSignedData(PGPSignature signature, InputStream signedData, PGPPublicKey signingKey)
            throws SignatureValidationException {
        try {
            signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signingKey);
            int read;
            while ((read = signedData.read()) != -1) {
                signature.update((byte) read);
            }
        } catch (PGPException e) {
            throw new SignatureValidationException("Cannot init signature.", e);
        } catch (IOException e) {
            throw new SignatureValidationException("Cannot update signature.", e);
        }
    }

    public static boolean verifyInitializedSignature(PGPSignature signature, PGPPublicKey signingKey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        signatureStructureIsAcceptable(signingKey, policy).verify(signature);
        signatureIsEffective(validationDate).verify(signature);

        try {
            if (!signature.verify()) {
                throw new SignatureValidationException("Signature is not correct.");
            }
            return true;
        } catch (PGPException e) {
            throw new SignatureValidationException("Could not verify signature correctness.", e);
        }
    }

    public static boolean verifySignatureOverUserId(String userId, PGPSignature signature, PGPPublicKey primaryKey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        return verifySignatureOverUserId(userId, signature, primaryKey, primaryKey, policy, validationDate);
    }

    public static boolean verifySignatureOverUserId(String userId, PGPSignature signature, PGPPublicKey signingKey, PGPPublicKey keyWithUserId, Policy policy, Date validationDate)
            throws SignatureValidationException {
        SignatureType type = SignatureType.valueOf(signature.getSignatureType());
        switch (type) {
            case GENERIC_CERTIFICATION:
            case NO_CERTIFICATION:
            case CASUAL_CERTIFICATION:
            case POSITIVE_CERTIFICATION:
                return verifyUserIdCertification(userId, signature, signingKey, keyWithUserId, policy, validationDate);
            case CERTIFICATION_REVOCATION:
                return verifyUserIdRevocation(userId, signature, signingKey, keyWithUserId, policy, validationDate);
            default:
                throw new SignatureValidationException("Signature is not a valid user-id certification/revocation signature: " + type);
        }
    }

    public static boolean verifyUserIdCertification(String userId, PGPSignature signature, PGPPublicKey primaryKey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        return verifyUserIdCertification(userId, signature, primaryKey, primaryKey, policy, validationDate);
    }

    public static boolean verifyUserIdCertification(String userId, PGPSignature signature, PGPPublicKey signingKey, PGPPublicKey keyWithUserId, Policy policy, Date validationDate)
            throws SignatureValidationException {

        signatureIsCertification().verify(signature);
        signatureStructureIsAcceptable(signingKey, policy).verify(signature);
        signatureIsEffective(validationDate).verify(signature);
        correctSignatureOverUserId(userId, keyWithUserId, signingKey).verify(signature);

        return true;
    }
    public static boolean verifyUserIdRevocation(String userId, PGPSignature signature, PGPPublicKey primaryKey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        return verifyUserIdRevocation(userId, signature, primaryKey, primaryKey, policy, validationDate);
    }

    public static boolean verifyUserIdRevocation(String userId, PGPSignature signature, PGPPublicKey signingKey, PGPPublicKey keyWithUserId, Policy policy, Date validationDate)
            throws SignatureValidationException {
        signatureIsOfType(SignatureType.CERTIFICATION_REVOCATION).verify(signature);
        signatureStructureIsAcceptable(signingKey, policy).verify(signature);
        signatureIsEffective(validationDate).verify(signature);
        correctSignatureOverUserId(userId, keyWithUserId, signingKey).verify(signature);

        return true;
    }

    public static boolean verifyUserAttributesCertification(PGPUserAttributeSubpacketVector userAttributes,
                                                            PGPSignature signature, PGPPublicKey primaryKey,
                                                            Policy policy, Date validationDate)
            throws SignatureValidationException {
        return verifyUserAttributesCertification(userAttributes, signature, primaryKey, primaryKey, policy, validationDate);
    }

    public static boolean verifyUserAttributesCertification(PGPUserAttributeSubpacketVector userAttributes,
                                                            PGPSignature signature, PGPPublicKey signingKey,
                                                            PGPPublicKey keyWithUserAttributes, Policy policy,
                                                            Date validationDate)
            throws SignatureValidationException {
        signatureIsCertification().verify(signature);
        signatureStructureIsAcceptable(signingKey, policy).verify(signature);
        signatureIsEffective(validationDate).verify(signature);
        correctSignatureOverUserAttributes(userAttributes, keyWithUserAttributes, signingKey).verify(signature);

        return true;
    }

    public static boolean verifyUserAttributesRevocation(PGPUserAttributeSubpacketVector userAttributes,
                                                         PGPSignature signature, PGPPublicKey primaryKey,
                                                         Policy policy, Date validationDate)
            throws SignatureValidationException {
        return verifyUserAttributesRevocation(userAttributes, signature, primaryKey, primaryKey, policy, validationDate);
    }

    public static boolean verifyUserAttributesRevocation(PGPUserAttributeSubpacketVector userAttributes,
                                                         PGPSignature signature, PGPPublicKey signingKey,
                                                         PGPPublicKey keyWithUserAttributes, Policy policy,
                                                         Date validationDate)
            throws SignatureValidationException {
        signatureIsOfType(SignatureType.CERTIFICATION_REVOCATION).verify(signature);
        signatureStructureIsAcceptable(signingKey, policy).verify(signature);
        signatureIsEffective(validationDate).verify(signature);
        correctSignatureOverUserAttributes(userAttributes, keyWithUserAttributes, signingKey).verify(signature);

        return true;
    }

    public static boolean verifySubkeyBindingSignature(PGPSignature signature, PGPPublicKey primaryKey, PGPPublicKey subkey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        signatureIsOfType(SignatureType.SUBKEY_BINDING).verify(signature);
        signatureStructureIsAcceptable(primaryKey, policy).verify(signature);
        signatureIsEffective(validationDate).verify(signature);
        hasValidPrimaryKeyBindingSignatureIfRequired(primaryKey, subkey, policy, validationDate).verify(signature);
        correctSubkeyBindingSignature(primaryKey, subkey).verify(signature);

        return true;
    }

    public static boolean verifySubkeyBindingRevocation(PGPSignature signature, PGPPublicKey primaryKey, PGPPublicKey subkey, Policy policy, Date validationDate) throws SignatureValidationException {
        signatureIsOfType(SignatureType.SUBKEY_REVOCATION).verify(signature);
        signatureStructureIsAcceptable(primaryKey, policy).verify(signature);
        signatureIsEffective(validationDate).verify(signature);
        correctSignatureOverKey(primaryKey, subkey).verify(signature);

        return true;
    }

    public static boolean verifyDirectKeySignature(PGPSignature signature, PGPPublicKey primaryKey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        return verifyDirectKeySignature(signature, primaryKey, primaryKey, policy, validationDate);
    }

    public static boolean verifyDirectKeySignature(PGPSignature signature, PGPPublicKey signingKey, PGPPublicKey signedKey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        signatureIsOfType(SignatureType.DIRECT_KEY).verify(signature);
        signatureStructureIsAcceptable(signingKey, policy).verify(signature);
        signatureIsEffective(validationDate).verify(signature);
        correctSignatureOverKey(signingKey, signedKey).verify(signature);

        return true;
    }

    public static boolean verifyKeyRevocationSignature(PGPSignature signature, PGPPublicKey primaryKey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        signatureIsOfType(SignatureType.KEY_REVOCATION).verify(signature);
        signatureStructureIsAcceptable(primaryKey, policy).verify(signature);
        signatureIsEffective(validationDate).verify(signature);
        correctSignatureOverKey(primaryKey, primaryKey).verify(signature);

        return true;
    }

    private static SignatureValidator hasValidPrimaryKeyBindingSignatureIfRequired(PGPPublicKey primaryKey, PGPPublicKey subkey, Policy policy, Date validationDate) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                if (!PublicKeyAlgorithm.fromId(signature.getKeyAlgorithm()).isSigningCapable()) {
                    // subkey is not signing capable -> No need to process embedded sigs
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
                                signatureIsEffective(validationDate).verify(embedded);
                                correctPrimaryKeyBindingSignature(primaryKey, subkey).verify(embedded);

                                hasValidPrimaryKeyBinding = true;
                                break;
                            } catch (SignatureValidationException e) {
                                rejectedEmbeddedSigs.put(embedded, e);
                            }
                        }
                    }

                    if (!hasValidPrimaryKeyBinding) {
                        throw new SignatureValidationException("Missing primary key binding signature on signing capable subkey " + Long.toHexString(subkey.getKeyID()), rejectedEmbeddedSigs);
                    }
                } catch (PGPException e) {
                    throw new SignatureValidationException("Cannot process list of embedded signatures.", e);
                }
            }
        };
    }

    public static SignatureValidator signatureStructureIsAcceptable(PGPPublicKey signingKey, Policy policy) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                signatureIsNotMalformed(signingKey).verify(signature);
                signatureDoesNotHaveCriticalUnknownNotations(policy.getNotationRegistry()).verify(signature);
                signatureDoesNotHaveCriticalUnknownSubpackets().verify(signature);
                signatureUsesAcceptableHashAlgorithm(policy).verify(signature);
                signatureUsesAcceptablePublicKeyAlgorithm(policy, signingKey).verify(signature);
            }
        };
    }

    private static SignatureValidator signatureUsesAcceptablePublicKeyAlgorithm(Policy policy, PGPPublicKey signingKey) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                PublicKeyAlgorithm algorithm = PublicKeyAlgorithm.fromId(signingKey.getAlgorithm());
                int bitStrength = BCUtil.getBitStrenght(signingKey);
                if (!policy.getPublicKeyAlgorithmPolicy().isAcceptable(algorithm, bitStrength)) {
                    throw new SignatureValidationException("Signature was made using unacceptable key. " +
                            algorithm + " (" + bitStrength + " bits) is not acceptable according to the public key algorithm policy.");
                }
            }
        };
    }

    private static SignatureValidator signatureUsesAcceptableHashAlgorithm(Policy policy) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                HashAlgorithm hashAlgorithm = HashAlgorithm.fromId(signature.getHashAlgorithm());
                Policy.HashAlgorithmPolicy hashAlgorithmPolicy = getHashAlgorithmPolicyForSignature(signature, policy);

                if (!hashAlgorithmPolicy.isAcceptable(signature.getHashAlgorithm())) {
                    throw new SignatureValidationException("Signature uses unacceptable hash algorithm " + hashAlgorithm);
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
    private static Policy.HashAlgorithmPolicy getHashAlgorithmPolicyForSignature(PGPSignature signature, Policy policy) {
        Policy.HashAlgorithmPolicy hashAlgorithmPolicy = null;
        SignatureType type = SignatureType.valueOf(signature.getSignatureType());
        if (type == SignatureType.CERTIFICATION_REVOCATION || type == SignatureType.KEY_REVOCATION || type == SignatureType.SUBKEY_REVOCATION) {
            hashAlgorithmPolicy = policy.getRevocationSignatureHashAlgorithmPolicy();
        } else {
            hashAlgorithmPolicy = policy.getSignatureHashAlgorithmPolicy();
        }
        return hashAlgorithmPolicy;
    }

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
                        throw new SignatureValidationException("Signature contains unknown critical notation '" + notation.getNotationName() + "' in its hashed area.");
                    }
                }
            }
        };
    }

    public static SignatureValidator signatureDoesNotHaveCriticalUnknownSubpackets() {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                PGPSignatureSubpacketVector hashedSubpackets = signature.getHashedSubPackets();
                for (int criticalTag : hashedSubpackets.getCriticalTags()) {
                    try {
                        SignatureSubpacket.fromCode(criticalTag);
                    } catch (IllegalArgumentException e) {
                        throw new SignatureValidationException("Signature contains unknown critical subpacket of type " + Long.toHexString(criticalTag));
                    }
                }
            }
        };
    }

    public static SignatureValidator signatureIsEffective(Date validationDate) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                signatureIsAlreadyEffective(validationDate).verify(signature);
                signatureIsNotYetExpired(validationDate).verify(signature);
            }
        };
    }

    public static SignatureValidator signatureIsAlreadyEffective(Date validationDate) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                Date signatureCreationTime = SignatureSubpacketsUtil.getSignatureCreationTime(signature).getTime();
                // Hard revocations are always effective
                if (SignatureUtils.isHardRevocation(signature)) {
                    return;
                }

                if (signatureCreationTime.after(validationDate)) {
                    throw new SignatureValidationException("Signature was created at " + signatureCreationTime + " and is therefore not yet valid at " + validationDate);
                }
            }
        };
    }

    public static SignatureValidator signatureIsNotYetExpired(Date validationDate) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                // Hard revocations do not expire
                if (SignatureUtils.isHardRevocation(signature)) {
                    return;
                }

                Date signatureExpirationTime = SignatureSubpacketsUtil.getSignatureExpirationTimeAsDate(signature);
                if (signatureExpirationTime != null && signatureExpirationTime.before(validationDate)) {
                    throw new SignatureValidationException("Signature is already expired (expiration: " + signatureExpirationTime + ", validation: " + validationDate + ")");
                }
            }
        };
    }

    public static SignatureValidator signatureIsNotMalformed(PGPPublicKey creator) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                signatureHasHashedCreationTime().verify(signature);
                signatureDoesNotPredateSigningKey(creator).verify(signature);
                signatureDoesNotPredateSigningKeyBindingDate(creator).verify(signature);
            }
        };
    }

    public static SignatureValidator signatureHasHashedCreationTime() {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                SignatureCreationTime creationTime = SignatureSubpacketsUtil.getSignatureCreationTime(signature);
                if (creationTime == null) {
                    throw new SignatureValidationException("Malformed signature. Signature has no signature creation time subpacket in its hashed area.");
                }
            }
        };
    }

    public static SignatureValidator signatureDoesNotPredateSigningKey(PGPPublicKey key) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                // TODO: Uncommenting the code below would mean that fake issuers would become a problem for sig verification
                /*
                long keyId = signature.getKeyID();
                if (keyId == 0) {
                    OpenPgpV4Fingerprint fingerprint = SignatureSubpacketsUtil.getIssuerFingerprintAsOpenPgpV4Fingerprint(signature);
                    if (fingerprint == null) {
                        throw new SignatureValidationException("Signature does not contain an issuer-id, neither an issuer-fingerprint subpacket.");
                    }
                    keyId = fingerprint.getKeyId();
                }
                if (keyId != key.getKeyID()) {
                    throw new IllegalArgumentException("Signature was not created using key " + Long.toHexString(key.getKeyID()));
                }
                 */

                Date keyCreationTime = key.getCreationTime();
                Date signatureCreationTime = signature.getCreationTime();

                if (keyCreationTime.after(signatureCreationTime)) {
                    throw new SignatureValidationException("Signature predates its signing key (key creation: " + keyCreationTime + ", signature creation: " + signatureCreationTime + ")");
                }
            }
        };
    }

    public static SignatureValidator signatureDoesNotPredateSigningKeyBindingDate(PGPPublicKey signingKey) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                if (signingKey.isMasterKey()) {
                    return;
                }
                boolean predatesBindingSig = true;
                Iterator<PGPSignature> bindingSignatures = signingKey.getSignaturesOfType(SignatureType.SUBKEY_BINDING.getCode());
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
                    throw new SignatureValidationException("Signature was created before the signing key was bound to the key ring.");
                }
            }
        };
    }

    public static SignatureValidator correctSubkeyBindingSignature(PGPPublicKey primaryKey, PGPPublicKey subkey) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                if (primaryKey.getKeyID() == subkey.getKeyID()) {
                    throw new SignatureValidationException("Primary key cannot be its own subkey.");
                }
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), primaryKey);
                    boolean valid = signature.verifyCertification(primaryKey, subkey);
                    if (!valid) {
                        throw new SignatureValidationException("Signature is not correct.");
                    }
                } catch (PGPException e) {
                    throw new SignatureValidationException("Cannot verify subkey binding signature correctness", e);
                }
            }
        };
    }

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
                } catch (PGPException e) {
                    throw new SignatureValidationException("Cannot verify primary key binding signature correctness", e);
                }
            }
        };
    }

    public static SignatureValidator correctSignatureOverKey(PGPPublicKey signer, PGPPublicKey signee) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signer);
                    boolean valid = false;
                    if (signer.getKeyID() != signee.getKeyID()) {
                        valid = signature.verifyCertification(signer, signee);
                    } else {
                        valid = signature.verifyCertification(signee);
                    }
                    if (!valid) {
                        throw new SignatureValidationException("Signature is not correct.");
                    }
                } catch (PGPException e) {
                    throw new SignatureValidationException("Cannot verify direct-key signature correctness", e);
                }
            }
        };
    }

    public static SignatureValidator signatureIsCertification() {
        return signatureIsOfType(
                SignatureType.POSITIVE_CERTIFICATION,
                SignatureType.CASUAL_CERTIFICATION,
                SignatureType.GENERIC_CERTIFICATION,
                SignatureType.NO_CERTIFICATION);
    }

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
                    throw new SignatureValidationException("Signature is of type " + type + " while only " + Arrays.toString(signatureTypes) + " are allowed here.");
                }
            }
        };
    }

    public static SignatureValidator correctSignatureOverUserId(String userId, PGPPublicKey certifiedKey, PGPPublicKey certifyingKey) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), certifyingKey);
                    boolean valid = signature.verifyCertification(userId, certifiedKey);
                    if (!valid) {
                        throw new SignatureValidationException("Signature over user-id '" + userId + "' is not correct.");
                    }
                } catch (PGPException e) {
                    throw new SignatureValidationException("Cannot verify signature over user-id '" + userId + "'.", e);
                }
            }
        };
    }

    public static SignatureValidator correctSignatureOverUserAttributes(PGPUserAttributeSubpacketVector userAttributes, PGPPublicKey certifiedKey, PGPPublicKey certifyingKey) {
        return new SignatureValidator() {
            @Override
            public void verify(PGPSignature signature) throws SignatureValidationException {
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), certifyingKey);
                    boolean valid = signature.verifyCertification(userAttributes, certifiedKey);
                    if (!valid) {
                        throw new SignatureValidationException("Signature over user-attribute vector is not correct.");
                    }
                } catch (PGPException e) {
                    throw new SignatureValidationException("Cannot verify signature over user-attribute vector.", e);
                }
            }
        };
    }

}
