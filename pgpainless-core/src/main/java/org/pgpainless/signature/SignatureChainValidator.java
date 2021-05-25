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

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.SignerUserID;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

/**
 * This class implements validity checks on OpenPGP signatures.
 * Its responsibilities are checking if a signing key was eligible to create a certain signature
 * and if the signature is valid at the time of validation.
 */
public class SignatureChainValidator {

    private static final Logger LOGGER = Logger.getLogger(SignatureChainValidator.class.getName());

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
    public static boolean validateSigningKey(PGPSignature signature, PGPPublicKeyRing signingKeyRing, Policy policy)
            throws SignatureValidationException {

        Map<PGPSignature, Exception> rejections = new ConcurrentHashMap<>();

        PGPPublicKey signingSubkey = signingKeyRing.getPublicKey(signature.getKeyID());
        if (signingSubkey == null) {
            throw new SignatureValidationException("Provided key ring does not contain a subkey with id " + Long.toHexString(signature.getKeyID()));
        }

        PGPPublicKey primaryKey = signingKeyRing.getPublicKey();

        // Key-Revocation Signatures
        List<PGPSignature> directKeySignatures = new ArrayList<>();
        Iterator<PGPSignature> primaryKeyRevocationIterator = primaryKey.getSignaturesOfType(SignatureType.KEY_REVOCATION.getCode());
        while (primaryKeyRevocationIterator.hasNext()) {
            PGPSignature revocation = primaryKeyRevocationIterator.next();
            try {
                if (SignatureValidator.verifyKeyRevocationSignature(revocation, primaryKey, policy, signature.getCreationTime())) {
                    directKeySignatures.add(revocation);
                }
            } catch (SignatureValidationException e) {
                rejections.put(revocation, e);
                LOGGER.log(Level.FINE, "Rejecting key revocation signature.", e);
            }
        }

        // Direct-Key Signatures
        Iterator<PGPSignature> keySignatures = primaryKey.getSignaturesOfType(SignatureType.DIRECT_KEY.getCode());
        while (keySignatures.hasNext()) {
            PGPSignature keySignature = keySignatures.next();
            try {
                if (SignatureValidator.verifyDirectKeySignature(keySignature, primaryKey, policy, signature.getCreationTime())) {
                    directKeySignatures.add(keySignature);
                }
            } catch (SignatureValidationException e) {
                rejections.put(keySignature, e);
                LOGGER.log(Level.FINE, "Rejecting key signature.", e);
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
                try {
                    if (SignatureValidator.verifySignatureOverUserId(userId, userIdSig, primaryKey, policy, signature.getCreationTime())) {
                        signaturesOnUserId.add(userIdSig);
                    }
                } catch (SignatureValidationException e) {
                    rejections.put(userIdSig, e);
                    LOGGER.log(Level.FINE, "Rejecting user-id signature.", e);
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
                    LOGGER.log(Level.FINE, "User-ID '" + userId + "' is revoked.");
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
        if (signerUserID != null) {
            PGPSignature userIdSig = userIdSignatures.get(signerUserID.getID()).get(0);
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
                try {
                    if (SignatureValidator.verifySubkeyBindingRevocation(revocation, primaryKey, signingSubkey, policy, signature.getCreationTime())) {
                        subkeySigs.add(revocation);
                    }
                } catch (SignatureValidationException e) {
                    rejections.put(revocation, e);
                    LOGGER.log(Level.FINE, "Rejecting subkey revocation signature.", e);
                }
            }

            Iterator<PGPSignature> bindingSigs = signingSubkey.getSignaturesOfType(SignatureType.SUBKEY_BINDING.getCode());
            while (bindingSigs.hasNext()) {
                PGPSignature bindingSig = bindingSigs.next();
                try {
                    if (SignatureValidator.verifySubkeyBindingSignature(bindingSig, primaryKey, signingSubkey, policy, signature.getCreationTime())) {
                        subkeySigs.add(bindingSig);
                    }
                } catch (SignatureValidationException e) {
                    rejections.put(bindingSig, e);
                    LOGGER.log(Level.FINE, "Rejecting subkey binding signature.", e);
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
    public static boolean validateSignatureChain(PGPSignature signature,
                                                 InputStream signedData,
                                                 PGPPublicKeyRing signingKeyRing,
                                                 Policy policy,
                                                 Date validationDate)
            throws SignatureValidationException {
        validateSigningKey(signature, signingKeyRing, policy);
        return SignatureValidator.verifyUninitializedSignature(signature, signedData, signingKeyRing.getPublicKey(signature.getKeyID()), policy, validationDate);
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
    public static boolean validateSignature(PGPSignature signature, PGPPublicKeyRing verificationKeys, Policy policy)
            throws SignatureValidationException {
        validateSigningKey(signature, verificationKeys, policy);
        PGPPublicKey signingKey = verificationKeys.getPublicKey(signature.getKeyID());
        SignatureValidator.verifyInitializedSignature(signature, signingKey, policy, signature.getCreationTime());
        return true;
    }
}
