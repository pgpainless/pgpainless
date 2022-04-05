// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer;

import static org.pgpainless.signature.consumer.SignatureVerifier.verifyOnePassSignature;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.SignerUserID;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A collection of static methods that validate signing certificates (public keys) and verify signature correctness.
 */
public final class CertificateValidator {

    private CertificateValidator() {

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateValidator.class);

    /**
     * Check if the signing key was eligible to create the provided signature.
     *
     * That entails:
     * - Check, if the primary key is being revoked via key-revocation signatures.
     * - Check, if the keys user-ids are revoked or not bound.
     * - Check, if the signing subkey is revoked or expired.
     * - Check, if the signing key is not capable of signing
     *
     * @param signature signature
     * @param signingKeyRing signing key ring
     * @param policy validation policy
     * @return true if the signing key was eligible to create the signature
     * @throws SignatureValidationException in case of a validation constraint violation
     */
    public static boolean validateCertificate(PGPSignature signature, PGPPublicKeyRing signingKeyRing, Policy policy)
            throws SignatureValidationException {

        Map<PGPSignature, Exception> rejections = new ConcurrentHashMap<>();
        long keyId = SignatureUtils.determineIssuerKeyId(signature);
        PGPPublicKey signingSubkey = signingKeyRing.getPublicKey(keyId);
        if (signingSubkey == null) {
            throw new SignatureValidationException("Provided key ring does not contain a subkey with id " + Long.toHexString(keyId));
        }

        PGPPublicKey primaryKey = signingKeyRing.getPublicKey();

        // Key-Revocation Signatures
        List<PGPSignature> directKeySignatures = new ArrayList<>();
        Iterator<PGPSignature> primaryKeyRevocationIterator = primaryKey.getSignaturesOfType(SignatureType.KEY_REVOCATION.getCode());
        while (primaryKeyRevocationIterator.hasNext()) {
            PGPSignature revocation = primaryKeyRevocationIterator.next();
            if (revocation.getKeyID() != primaryKey.getKeyID()) {
                // Revocation was not made by primary key, skip
                // TODO: What about external revocation keys?
            }
            try {
                if (SignatureVerifier.verifyKeyRevocationSignature(revocation, primaryKey, policy, signature.getCreationTime())) {
                    directKeySignatures.add(revocation);
                }
            } catch (SignatureValidationException e) {
                rejections.put(revocation, e);
                LOGGER.debug("Rejecting key revocation signature: {}", e.getMessage(), e);
            }
        }

        // Direct-Key Signatures
        Iterator<PGPSignature> keySignatures = primaryKey.getSignaturesOfType(SignatureType.DIRECT_KEY.getCode());
        while (keySignatures.hasNext()) {
            PGPSignature keySignature = keySignatures.next();
            if (keySignature.getKeyID() != primaryKey.getKeyID()) {
                // Signature was not made by primary key, skip
                continue;
            }
            try {
                if (SignatureVerifier.verifyDirectKeySignature(keySignature, primaryKey, policy, signature.getCreationTime())) {
                    directKeySignatures.add(keySignature);
                }
            } catch (SignatureValidationException e) {
                rejections.put(keySignature, e);
                LOGGER.debug("Rejecting key signature: {}", e.getMessage(), e);
            }
        }

        Collections.sort(directKeySignatures, new SignatureValidityComparator(SignatureCreationDateComparator.Order.NEW_TO_OLD));
        if (!directKeySignatures.isEmpty()) {
            if (directKeySignatures.get(0).getSignatureType() == SignatureType.KEY_REVOCATION.getCode()) {
                throw new SignatureValidationException("Primary key has been revoked.");
            }
        }

        // User-ID signatures (certifications, revocations)
        Iterator<String> userIds = primaryKey.getUserIDs();
        Map<String, List<PGPSignature>> userIdSignatures = new ConcurrentHashMap<>();
        while (userIds.hasNext()) {
            List<PGPSignature> signaturesOnUserId = new ArrayList<>();
            String userId = userIds.next();
            Iterator<PGPSignature> userIdSigs = primaryKey.getSignaturesForID(userId);
            while (userIdSigs.hasNext()) {
                PGPSignature userIdSig = userIdSigs.next();
                if (userIdSig.getKeyID() != primaryKey.getKeyID()) {
                    // Sig was made by external key, skip
                    continue;
                }
                try {
                    if (SignatureVerifier.verifySignatureOverUserId(userId, userIdSig, primaryKey, policy, signature.getCreationTime())) {
                        signaturesOnUserId.add(userIdSig);
                    }
                } catch (SignatureValidationException e) {
                    rejections.put(userIdSig, e);
                    LOGGER.debug("Rejecting user-id signature: {}", e.getMessage(), e);
                }
            }
            Collections.sort(signaturesOnUserId, new SignatureValidityComparator(SignatureCreationDateComparator.Order.NEW_TO_OLD));
            userIdSignatures.put(userId, signaturesOnUserId);
        }

        boolean anyUserIdValid = false;
        for (String userId : userIdSignatures.keySet()) {
            if (!userIdSignatures.get(userId).isEmpty()) {
                PGPSignature current = userIdSignatures.get(userId).get(0);
                if (current.getSignatureType() == SignatureType.CERTIFICATION_REVOCATION.getCode()) {
                    LOGGER.debug("User-ID '{}' is revoked.", userId);
                } else {
                    anyUserIdValid = true;
                }
            }
        }

        if (!anyUserIdValid) {
            throw new SignatureValidationException("No valid user-id found.", rejections);
        }

        // Specific signer user-id
        SignerUserID signerUserID = SignatureSubpacketsUtil.getSignerUserID(signature);
        if (signerUserID != null && policy.getSignerUserIdValidationLevel() == Policy.SignerUserIdValidationLevel.STRICT) {
            List<PGPSignature> signerUserIdSigs = userIdSignatures.get(signerUserID.getID());
            if (signerUserIdSigs == null || signerUserIdSigs.isEmpty()) {
                throw new SignatureValidationException("Signature was allegedly made by user-id '" + signerUserID.getID() +
                        "' but we have no valid signatures for that on the certificate.");
            }

            PGPSignature userIdSig = signerUserIdSigs.get(0);
            if (userIdSig.getSignatureType() == SignatureType.CERTIFICATION_REVOCATION.getCode()) {
                throw new SignatureValidationException("Signature was made with user-id '" + signerUserID.getID() + "' which is revoked.");
            }
        }

        if (signingSubkey == primaryKey) {
            if (!directKeySignatures.isEmpty()) {
                if (KeyFlag.hasKeyFlag(SignatureSubpacketsUtil.getKeyFlags(directKeySignatures.get(0)).getFlags(), KeyFlag.SIGN_DATA)) {
                    return true;
                }
            }
        } // Subkey Binding Signatures / Subkey Revocation Signatures
        else {
            List<PGPSignature> subkeySigs = new ArrayList<>();
            Iterator<PGPSignature> bindingRevocations = signingSubkey.getSignaturesOfType(SignatureType.SUBKEY_REVOCATION.getCode());
            while (bindingRevocations.hasNext()) {
                PGPSignature revocation = bindingRevocations.next();
                if (revocation.getKeyID() != primaryKey.getKeyID()) {
                    // Subkey Revocation was not made by primary key, skip
                    continue;
                }
                try {
                    if (SignatureVerifier.verifySubkeyBindingRevocation(revocation, primaryKey, signingSubkey, policy, signature.getCreationTime())) {
                        subkeySigs.add(revocation);
                    }
                } catch (SignatureValidationException e) {
                    rejections.put(revocation, e);
                    LOGGER.debug("Rejecting subkey revocation signature: {}", e.getMessage(), e);
                }
            }

            Iterator<PGPSignature> bindingSigs = signingSubkey.getSignaturesOfType(SignatureType.SUBKEY_BINDING.getCode());
            while (bindingSigs.hasNext()) {
                PGPSignature bindingSig = bindingSigs.next();
                try {
                    if (SignatureVerifier.verifySubkeyBindingSignature(bindingSig, primaryKey, signingSubkey, policy, signature.getCreationTime())) {
                        subkeySigs.add(bindingSig);
                    }
                } catch (SignatureValidationException e) {
                    rejections.put(bindingSig, e);
                    LOGGER.debug("Rejecting subkey binding signature: {}", e.getMessage(), e);
                }
            }

            Collections.sort(subkeySigs, new SignatureValidityComparator(SignatureCreationDateComparator.Order.NEW_TO_OLD));
            if (subkeySigs.isEmpty()) {
                throw new SignatureValidationException("Subkey is not bound.", rejections);
            }

            PGPSignature currentSig = subkeySigs.get(0);
            if (currentSig.getSignatureType() == SignatureType.SUBKEY_REVOCATION.getCode()) {
                throw new SignatureValidationException("Subkey is revoked.");
            }

            KeyFlags keyFlags = SignatureSubpacketsUtil.getKeyFlags(currentSig);
            if (keyFlags == null) {
                if (directKeySignatures.isEmpty()) {
                    throw new SignatureValidationException("Signature was made by key which is not capable of signing (no keyflags on binding sig, no direct-key sig).");
                }
                PGPSignature directKeySig = directKeySignatures.get(0);
                KeyFlags directKeyFlags = SignatureSubpacketsUtil.getKeyFlags(directKeySig);
                if (!KeyFlag.hasKeyFlag(directKeyFlags.getFlags(), KeyFlag.SIGN_DATA)) {
                    throw new SignatureValidationException("Signature was made by key which is not capable of signing (no keyflags on binding sig, no SIGN flag on direct-key sig).");
                }
            } else if (!KeyFlag.hasKeyFlag(keyFlags.getFlags(), KeyFlag.SIGN_DATA)) {
                throw new SignatureValidationException("Signature was made by key which is not capable of signing (no SIGN flag on binding sig).");
            }
        }
        return true;
    }

    /**
     * Validate the given signing key and then verify the given signature while parsing out the signed data.
     * Uninitialized means that no signed data has been read and the hash generators state has not yet been updated.
     *
     * @param signature uninitialized signature
     * @param signedData input stream containing signed data
     * @param signingKeyRing key ring containing signing key
     * @param policy validation policy
     * @param validationDate date of validation
     * @return true if the signature is valid, false otherwise
     * @throws SignatureValidationException for validation constraint violations
     */
    public static boolean validateCertificateAndVerifyUninitializedSignature(PGPSignature signature,
                                                                             InputStream signedData,
                                                                             PGPPublicKeyRing signingKeyRing,
                                                                             Policy policy,
                                                                             Date validationDate)
            throws SignatureValidationException {
        validateCertificate(signature, signingKeyRing, policy);
        long keyId = SignatureUtils.determineIssuerKeyId(signature);
        return SignatureVerifier.verifyUninitializedSignature(signature, signedData, signingKeyRing.getPublicKey(keyId), policy, validationDate);
    }

    /**
     * Validate the signing key and the given initialized signature.
     * Initialized means that the signatures hash generator has already been updated by reading the signed data completely.
     *
     * @param signature initialized signature
     * @param verificationKeys key ring containing the verification key
     * @param policy validation policy
     * @return true if the signature is valid, false otherwise
     * @throws SignatureValidationException in case of a validation constraint violation
     */
    public static boolean validateCertificateAndVerifyInitializedSignature(PGPSignature signature, PGPPublicKeyRing verificationKeys, Policy policy)
            throws SignatureValidationException {
        validateCertificate(signature, verificationKeys, policy);
        long keyId = SignatureUtils.determineIssuerKeyId(signature);
        PGPPublicKey signingKey = verificationKeys.getPublicKey(keyId);
        SignatureVerifier.verifyInitializedSignature(signature, signingKey, policy, signature.getCreationTime());
        return true;
    }

    /**
     * Validate the signing key certificate and the given {@link OnePassSignatureCheck}.
     *
     * @param onePassSignature corresponding one-pass-signature
     * @param policy policy
     * @return true if the certificate is valid and the signature is correct, false otherwise.
     * @throws SignatureValidationException in case of a validation error
     */
    public static boolean validateCertificateAndVerifyOnePassSignature(OnePassSignatureCheck onePassSignature, Policy policy)
            throws SignatureValidationException {
        PGPSignature signature = onePassSignature.getSignature();
        validateCertificate(signature, onePassSignature.getVerificationKeys(), policy);
        PGPPublicKey signingKey = onePassSignature.getVerificationKeys().getPublicKey(signature.getKeyID());
        verifyOnePassSignature(signature, signingKey, onePassSignature, policy);
        return true;
    }
}
