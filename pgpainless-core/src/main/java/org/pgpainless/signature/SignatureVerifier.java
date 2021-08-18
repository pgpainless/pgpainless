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
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.policy.Policy;

/**
 * Collection of static methods for signature verification.
 * Signature verification entails validation of certain criteria (see {@link SignatureValidator}), as well as
 * cryptographic verification of signature correctness.
 */
public final class SignatureVerifier {

    private SignatureVerifier() {

    }

    /**
     * Verify a signature (certification or revocation) over a user-id.
     *
     * @param userId user-id
     * @param signature certification signature
     * @param signingKey key that created the certification
     * @param keyWithUserId key carrying the user-id
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if signature verification is successful
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
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

    /**
     * Verify a certification self-signature over a user-id.
     *
     * @param userId user-id
     * @param signature certification signature
     * @param primaryKey primary key
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if the self-signature is verified successfully
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifyUserIdCertification(String userId, PGPSignature signature, PGPPublicKey primaryKey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        return verifyUserIdCertification(userId, signature, primaryKey, primaryKey, policy, validationDate);
    }

    /**
     * Verify a user-id certification.
     *
     * @param userId user-id
     * @param signature certification signature
     * @param signingKey key that created the certification
     * @param keyWithUserId primary key that carries the user-id
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if signature verification is successful
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifyUserIdCertification(String userId, PGPSignature signature, PGPPublicKey signingKey, PGPPublicKey keyWithUserId, Policy policy, Date validationDate)
            throws SignatureValidationException {
        SignatureValidator.signatureIsCertification().verify(signature);
        SignatureValidator.signatureStructureIsAcceptable(signingKey, policy).verify(signature);
        SignatureValidator.signatureIsEffective(validationDate).verify(signature);
        SignatureValidator.correctSignatureOverUserId(userId, keyWithUserId, signingKey).verify(signature);

        return true;
    }

    /**
     * Verify a user-id revocation self-signature.
     *
     * @param userId user-id
     * @param signature user-id revocation signature
     * @param primaryKey primary key
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if the user-id revocation signature is successfully verified
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifyUserIdRevocation(String userId, PGPSignature signature, PGPPublicKey primaryKey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        return verifyUserIdRevocation(userId, signature, primaryKey, primaryKey, policy, validationDate);
    }

    /**
     * Verify a user-id revocation signature.
     *
     * @param userId user-id
     * @param signature revocation signature
     * @param signingKey key that created the revocation signature
     * @param keyWithUserId primary key carrying the user-id
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if the user-id revocation signature is successfully verified
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifyUserIdRevocation(String userId, PGPSignature signature, PGPPublicKey signingKey, PGPPublicKey keyWithUserId, Policy policy, Date validationDate)
            throws SignatureValidationException {
        SignatureValidator.signatureIsOfType(SignatureType.CERTIFICATION_REVOCATION).verify(signature);
        SignatureValidator.signatureStructureIsAcceptable(signingKey, policy).verify(signature);
        SignatureValidator.signatureIsEffective(validationDate).verify(signature);
        SignatureValidator.correctSignatureOverUserId(userId, keyWithUserId, signingKey).verify(signature);

        return true;
    }

    /**
     * Verify a certification self-signature over a user-attributes packet.
     *
     * @param userAttributes user attributes
     * @param signature certification self-signature
     * @param primaryKey primary key that carries the user-attributes
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if the signature can be verified successfully
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifyUserAttributesCertification(PGPUserAttributeSubpacketVector userAttributes,
                                                            PGPSignature signature, PGPPublicKey primaryKey,
                                                            Policy policy, Date validationDate)
            throws SignatureValidationException {
        return verifyUserAttributesCertification(userAttributes, signature, primaryKey, primaryKey, policy, validationDate);
    }

    /**
     * Verify a certification signature over a user-attributes packet.
     *
     * @param userAttributes user attributes
     * @param signature certification signature
     * @param signingKey key that created the user-attributes certification
     * @param keyWithUserAttributes key that carries the user-attributes certification
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if the signature can be verified successfully
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifyUserAttributesCertification(PGPUserAttributeSubpacketVector userAttributes,
                                                            PGPSignature signature, PGPPublicKey signingKey,
                                                            PGPPublicKey keyWithUserAttributes, Policy policy,
                                                            Date validationDate)
            throws SignatureValidationException {
        SignatureValidator.signatureIsCertification().verify(signature);
        SignatureValidator.signatureStructureIsAcceptable(signingKey, policy).verify(signature);
        SignatureValidator.signatureIsEffective(validationDate).verify(signature);
        SignatureValidator.correctSignatureOverUserAttributes(userAttributes, keyWithUserAttributes, signingKey).verify(signature);

        return true;
    }

    /**
     * Verify a user-attributes revocation self-signature.
     *
     * @param userAttributes user-attributes
     * @param signature user-attributes revocation signature
     * @param primaryKey primary key that carries the user-attributes
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if the revocation signature can be verified successfully
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifyUserAttributesRevocation(PGPUserAttributeSubpacketVector userAttributes,
                                                         PGPSignature signature, PGPPublicKey primaryKey,
                                                         Policy policy, Date validationDate)
            throws SignatureValidationException {
        return verifyUserAttributesRevocation(userAttributes, signature, primaryKey, primaryKey, policy, validationDate);
    }

    /**
     * Verify a user-attributes revocation signature.
     *
     * @param userAttributes user-attributes
     * @param signature revocation signature
     * @param signingKey revocation key
     * @param keyWithUserAttributes key that carries the user-attributes
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if the revocation signature can be verified successfully
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifyUserAttributesRevocation(PGPUserAttributeSubpacketVector userAttributes,
                                                         PGPSignature signature, PGPPublicKey signingKey,
                                                         PGPPublicKey keyWithUserAttributes, Policy policy,
                                                         Date validationDate)
            throws SignatureValidationException {
        SignatureValidator.signatureIsOfType(SignatureType.CERTIFICATION_REVOCATION).verify(signature);
        SignatureValidator.signatureStructureIsAcceptable(signingKey, policy).verify(signature);
        SignatureValidator.signatureIsEffective(validationDate).verify(signature);
        SignatureValidator.correctSignatureOverUserAttributes(userAttributes, keyWithUserAttributes, signingKey).verify(signature);

        return true;
    }

    /**
     * Verify a subkey binding signature.
     *
     * @param signature binding signature
     * @param primaryKey primary key
     * @param subkey subkey
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if the binding signature can be verified successfully
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifySubkeyBindingSignature(PGPSignature signature, PGPPublicKey primaryKey, PGPPublicKey subkey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        SignatureValidator.signatureIsOfType(SignatureType.SUBKEY_BINDING).verify(signature);
        SignatureValidator.signatureStructureIsAcceptable(primaryKey, policy).verify(signature);
        SignatureValidator.signatureIsEffective(validationDate).verify(signature);
        SignatureValidator.hasValidPrimaryKeyBindingSignatureIfRequired(primaryKey, subkey, policy, validationDate).verify(signature);
        SignatureValidator.correctSubkeyBindingSignature(primaryKey, subkey).verify(signature);

        return true;
    }

    /**
     * Verify a subkey revocation signature.
     *
     * @param signature subkey revocation signature
     * @param primaryKey primary key
     * @param subkey subkey
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if the subkey revocation signature can be verified successfully
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifySubkeyBindingRevocation(PGPSignature signature, PGPPublicKey primaryKey, PGPPublicKey subkey, Policy policy, Date validationDate) throws SignatureValidationException {
        SignatureValidator.signatureIsOfType(SignatureType.SUBKEY_REVOCATION).verify(signature);
        SignatureValidator.signatureStructureIsAcceptable(primaryKey, policy).verify(signature);
        SignatureValidator.signatureIsEffective(validationDate).verify(signature);
        SignatureValidator.correctSignatureOverKey(primaryKey, subkey).verify(signature);

        return true;
    }

    /**
     * Verify a direct-key self-signature.
     *
     * @param signature signature
     * @param primaryKey primary key
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if the signature can be verified successfully
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifyDirectKeySignature(PGPSignature signature, PGPPublicKey primaryKey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        return verifyDirectKeySignature(signature, primaryKey, primaryKey, policy, validationDate);
    }

    /**
     * Verify a direct-key signature.
     *
     * @param signature signature
     * @param signingKey signing key
     * @param signedKey signed key
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if signature verification is successful
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifyDirectKeySignature(PGPSignature signature, PGPPublicKey signingKey, PGPPublicKey signedKey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        SignatureValidator.signatureIsOfType(SignatureType.DIRECT_KEY).verify(signature);
        SignatureValidator.signatureStructureIsAcceptable(signingKey, policy).verify(signature);
        SignatureValidator.signatureIsEffective(validationDate).verify(signature);
        SignatureValidator.correctSignatureOverKey(signingKey, signedKey).verify(signature);

        return true;
    }

    /**
     * Verify a key revocation signature.
     *
     * @param signature signature
     * @param primaryKey primary key
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if signature verification is successful
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifyKeyRevocationSignature(PGPSignature signature, PGPPublicKey primaryKey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        SignatureValidator.signatureIsOfType(SignatureType.KEY_REVOCATION).verify(signature);
        SignatureValidator.signatureStructureIsAcceptable(primaryKey, policy).verify(signature);
        SignatureValidator.signatureIsEffective(validationDate).verify(signature);
        SignatureValidator.correctSignatureOverKey(primaryKey, primaryKey).verify(signature);

        return true;
    }

    /**
     * Initialize a signature and verify it afterwards by updating it with the signed data.
     *
     * @param signature OpenPGP signature
     * @param signedData input stream containing the signed data
     * @param signingKey the key that created the signature
     * @param policy policy
     * @param validationDate reference date of signature verification
     * @return true if the signature is successfully verified
     *
     * @throws SignatureValidationException if the signature verification fails for some reason
     */
    public static boolean verifyUninitializedSignature(PGPSignature signature, InputStream signedData, PGPPublicKey signingKey, Policy policy, Date validationDate) throws SignatureValidationException {
        initializeSignatureAndUpdateWithSignedData(signature, signedData, signingKey);
        return verifyInitializedSignature(signature, signingKey, policy, validationDate);
    }

    /**
     * Initialize a signature and then update it with the signed data from the given {@link InputStream}.
     *
     * @param signature OpenPGP signature
     * @param signedData input stream containing signed data
     * @param signingKey key that created the signature
     *
     * @throws SignatureValidationException in case the signature cannot be verified for some reason
     */
    public static void initializeSignatureAndUpdateWithSignedData(PGPSignature signature, InputStream signedData, PGPPublicKey signingKey)
            throws SignatureValidationException {
        try {
            signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signingKey);
            int read;
            byte[] buf = new byte[8192];
            while ((read = signedData.read(buf)) != -1) {
                signature.update(buf, 0, read);
            }
        } catch (PGPException e) {
            throw new SignatureValidationException("Cannot init signature.", e);
        } catch (IOException e) {
            throw new SignatureValidationException("Cannot update signature.", e);
        }
    }

    /**
     * Verify an initialized signature.
     * An initialized signature was already updated with the signed data.
     *
     * @param signature OpenPGP signature
     * @param signingKey key that created the signature
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if signature is verified successfully
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifyInitializedSignature(PGPSignature signature, PGPPublicKey signingKey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        SignatureValidator.wasPossiblyMadeByKey(signingKey).verify(signature);
        SignatureValidator.signatureStructureIsAcceptable(signingKey, policy).verify(signature);
        SignatureValidator.signatureIsEffective(validationDate).verify(signature);

        try {
            if (!signature.verify()) {
                throw new SignatureValidationException("Signature is not correct.");
            }
            return true;
        } catch (PGPException e) {
            throw new SignatureValidationException("Could not verify signature correctness.", e);
        }
    }

    public static boolean verifyOnePassSignature(PGPSignature signature, PGPPublicKey signingKey, OnePassSignature onePassSignature, Policy policy)
            throws SignatureValidationException {
        try {
            SignatureValidator.wasPossiblyMadeByKey(signingKey).verify(signature);
            SignatureValidator.signatureStructureIsAcceptable(signingKey, policy).verify(signature);
            SignatureValidator.signatureIsEffective().verify(signature);
        } catch (SignatureValidationException e) {
            throw new SignatureValidationException("Signature is not valid: " + e.getMessage(), e);
        }

        try {
            if (!onePassSignature.verify(signature)) {
                throw new SignatureValidationException("Bad signature of key " + Long.toHexString(signingKey.getKeyID()));
            }
        } catch (PGPException e) {
            throw new SignatureValidationException("Could not verify correctness of One-Pass-Signature: " + e.getMessage(), e);
        }

        return true;
    }

    /**
     * Verify a signature (certification or revocation) over a user-id.
     *
     * @param userId user-id
     * @param signature self-signature
     * @param primaryKey primary key that created the signature
     * @param policy policy
     * @param validationDate reference date for signature verification
     * @return true if the signature is successfully verified
     *
     * @throws SignatureValidationException if signature verification fails for some reason
     */
    public static boolean verifySignatureOverUserId(String userId, PGPSignature signature, PGPPublicKey primaryKey, Policy policy, Date validationDate)
            throws SignatureValidationException {
        return verifySignatureOverUserId(userId, signature, primaryKey, primaryKey, policy, validationDate);
    }
}
