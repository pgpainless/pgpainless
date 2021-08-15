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

import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.policy.Policy;
import org.pgpainless.util.CollectionUtils;

/**
 * Pick signatures from keys.
 *
 * The format of a V4 OpenPGP key is:
 *
 * Primary-Key
 *    [Revocation Self Signature]
 *    [Direct Key Signature...]
 *     User ID [Signature ...]
 *    [User ID [Signature ...] ...]
 *    [User Attribute [Signature ...] ...]
 *    [[Subkey [Binding-Signature-Revocation] Primary-Key-Binding-Signature] ...]
 */
public final class SignaturePicker {

    private SignaturePicker() {

    }

    /**
     * Pick the, at validation date most recent valid key revocation signature.
     * If there are hard revocation signatures, the latest hard revocation sig is picked, even if it was created after
     * validationDate or if it is already expired.
     *
     * @param keyRing key ring
     * @return most recent, valid key revocation signature
     */
    public static PGPSignature pickCurrentRevocationSelfSignature(PGPKeyRing keyRing, Policy policy, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();

        List<PGPSignature> signatures = getSortedSignaturesOfType(primaryKey, SignatureType.KEY_REVOCATION);
        PGPSignature mostCurrentValidSig = null;

        for (PGPSignature signature : signatures) {
            try {
                SignatureValidator.verifyKeyRevocationSignature(signature, primaryKey, policy, validationDate);
            } catch (SignatureValidationException e) {
                // Signature is not valid
                continue;
            }
            mostCurrentValidSig = signature;
        }

        return mostCurrentValidSig;
    }

    /**
     * Pick the, at validationDate most recent, valid direct key signature.
     * This method might return null, if there is no direct key self-signature which is valid at validationDate.
     *
     * @param keyRing key ring
     * @param validationDate validation date
     * @return direct-key self-signature
     */
    public static PGPSignature pickCurrentDirectKeySelfSignature(PGPKeyRing keyRing, Policy policy, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();
        return pickCurrentDirectKeySignature(primaryKey, primaryKey, policy, validationDate);
    }

    /**
     * Pick the, at validationDate, latest, valid direct key signature made by signingKey on signedKey.
     * This method might return null, if there is no direct key self signature which is valid at validationDate.
     *
     * @param signingKey key that created the signature
     * @param signedKey key that carries the signature
     * @param validationDate validation date
     * @return direct key sig
     */
    public static PGPSignature pickCurrentDirectKeySignature(PGPPublicKey signingKey, PGPPublicKey signedKey, Policy policy, Date validationDate) {
        List<PGPSignature> directKeySignatures = getSortedSignaturesOfType(signedKey, SignatureType.DIRECT_KEY);

        PGPSignature mostRecentDirectKeySigBySigningKey = null;
        for (PGPSignature signature : directKeySignatures) {
            try {
                SignatureValidator.verifyDirectKeySignature(signature, signingKey, signedKey, policy, validationDate);
            } catch (SignatureValidationException e) {
                // Direct key sig is not valid
                continue;
            }
            mostRecentDirectKeySigBySigningKey = signature;
        }

        return mostRecentDirectKeySigBySigningKey;
    }

    /**
     * Pick the, at validationDate, latest direct key signature.
     * This method might return an expired signature.
     * If there are more than one direct-key signature, and some of those are not expired, the latest non-expired
     * yet already effective direct-key signature will be returned.
     *
     * @param keyRing key ring
     * @param validationDate validation date
     * @return latest direct key signature
     */
    public static PGPSignature pickLatestDirectKeySignature(PGPKeyRing keyRing, Policy policy, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();
        return pickLatestDirectKeySignature(primaryKey, primaryKey, policy, validationDate);
    }

    /**
     * Pick the, at validationDate, latest direct key signature made by signingKey on signedKey.
     * This method might return an expired signature.
     * If a non-expired direct-key signature exists, the latest non-expired yet already effective direct-key
     * signature will be returned.
     *
     * @param signingKey signing key (key that made the sig)
     * @param signedKey signed key (key that carries the sig)
     * @param validationDate date of validation
     * @return latest direct key sig
     */
    public static PGPSignature pickLatestDirectKeySignature(PGPPublicKey signingKey, PGPPublicKey signedKey, Policy policy, Date validationDate) {
        List<PGPSignature> signatures = getSortedSignaturesOfType(signedKey, SignatureType.DIRECT_KEY);

        PGPSignature latestDirectKeySignature = null;
        for (PGPSignature signature : signatures) {
            try {
                SignatureValidator.signatureIsOfType(SignatureType.DIRECT_KEY).verify(signature);
                SignatureValidator.signatureStructureIsAcceptable(signingKey, policy).verify(signature);
                SignatureValidator.signatureIsAlreadyEffective(validationDate).verify(signature);
                // if the currently latest signature is not yet expired, check if the next candidate is not yet expired
                if (latestDirectKeySignature != null && !SignatureUtils.isSignatureExpired(latestDirectKeySignature, validationDate)) {
                    SignatureValidator.signatureIsNotYetExpired(validationDate).verify(signature);
                }
                SignatureValidator.correctSignatureOverKey(signingKey, signedKey).verify(signature);
            } catch (SignatureValidationException e) {
                // Direct key signature is not valid
                continue;
            }
            latestDirectKeySignature = signature;
        }

        return latestDirectKeySignature;
    }

    /**
     * Pick the, at validationDate most recent, valid user-id revocation signature.
     * If there are hard revocation signatures, the latest hard revocation sig is picked, even if it was created after
     * validationDate or if it is already expired.
     *
     * @param keyRing key ring
     * @param userId user-Id that gets revoked
     * @param validationDate validation date
     * @return revocation signature
     */
    public static PGPSignature pickCurrentUserIdRevocationSignature(PGPKeyRing keyRing, String userId, Policy policy, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();
        List<PGPSignature> signatures = getSortedSignaturesOfType(primaryKey, SignatureType.CERTIFICATION_REVOCATION);

        PGPSignature latestUserIdRevocation = null;
        for (PGPSignature signature : signatures) {
            try {
                SignatureValidator.verifyUserIdRevocation(userId, signature, primaryKey, policy, validationDate);
            } catch (SignatureValidationException e) {
                // User-id revocation is not valid
                continue;
            }
            latestUserIdRevocation = signature;
        }

        return latestUserIdRevocation;
    }

    /**
     * Pick the, at validationDate latest, valid certification self-signature for the given user-id.
     * This method might return null, if there is no certification self signature for that user-id which is valid
     * at validationDate.
     *
     * @param keyRing keyring
     * @param userId userid
     * @param validationDate validation date
     * @return user-id certification
     */
    public static PGPSignature pickCurrentUserIdCertificationSignature(PGPKeyRing keyRing, String userId, Policy policy, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();

        Iterator<PGPSignature> userIdSigIterator = primaryKey.getSignaturesForID(userId);
        List<PGPSignature> signatures = CollectionUtils.iteratorToList(userIdSigIterator);
        Collections.sort(signatures, new SignatureCreationDateComparator());

        PGPSignature mostRecentUserIdCertification = null;
        for (PGPSignature signature : signatures) {
            try {
                SignatureValidator.verifyUserIdCertification(userId, signature, primaryKey, policy, validationDate);
            } catch (SignatureValidationException e) {
                // User-id certification is not valid
                continue;
            }
            mostRecentUserIdCertification = signature;
        }

        return mostRecentUserIdCertification;
    }

    /**
     * Pick the, at validationDate latest certification self-signature for the given user-id.
     * This method might return an expired signature.
     * If a non-expired user-id certification signature exists, the latest non-expired yet already effective
     * user-id certification signature for the given user-id will be returned.
     *
     * @param keyRing keyring
     * @param userId userid
     * @param validationDate validation date
     * @return user-id certification
     */
    public static PGPSignature pickLatestUserIdCertificationSignature(PGPKeyRing keyRing, String userId, Policy policy, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();

        Iterator<PGPSignature> userIdSigIterator = primaryKey.getSignaturesForID(userId);
        List<PGPSignature> signatures = CollectionUtils.iteratorToList(userIdSigIterator);
        Collections.sort(signatures, new SignatureCreationDateComparator());

        PGPSignature latestUserIdCert = null;
        for (PGPSignature signature : signatures) {
            try {
                SignatureValidator.verifyWasPossiblyMadeByKey(primaryKey, signature);
                SignatureValidator.signatureIsCertification().verify(signature);
                SignatureValidator.signatureStructureIsAcceptable(primaryKey, policy).verify(signature);
                SignatureValidator.signatureIsAlreadyEffective(validationDate).verify(signature);
                // if the currently latest signature is not yet expired, check if the next candidate is not yet expired
                if (latestUserIdCert != null && !SignatureUtils.isSignatureExpired(latestUserIdCert, validationDate)) {
                    SignatureValidator.signatureIsNotYetExpired(validationDate).verify(signature);
                }
                SignatureValidator.correctSignatureOverUserId(userId, primaryKey, primaryKey).verify(signature);
            } catch (SignatureValidationException e) {
                // User-id certification is not valid
                continue;
            }

            latestUserIdCert = signature;
        }

        return latestUserIdCert;
    }

    /**
     * Pick the, at validationDate most recent, valid subkey revocation signature.
     * If there are hard revocation signatures, the latest hard revocation sig is picked, even if it was created after
     * validationDate or if it is already expired.
     *
     * @param keyRing keyring
     * @param subkey subkey
     * @param validationDate validation date
     * @return subkey revocation signature
     */
    public static PGPSignature pickCurrentSubkeyBindingRevocationSignature(PGPKeyRing keyRing, PGPPublicKey subkey, Policy policy, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();
        if (primaryKey.getKeyID() == subkey.getKeyID()) {
            throw new IllegalArgumentException("Primary key cannot have subkey binding revocations.");
        }

        List<PGPSignature> signatures = getSortedSignaturesOfType(subkey, SignatureType.SUBKEY_BINDING);
        PGPSignature latestSubkeyRevocation = null;

        for (PGPSignature signature : signatures) {
            try {
                SignatureValidator.verifySubkeyBindingRevocation(signature, primaryKey, subkey, policy, validationDate);
            } catch (SignatureValidationException e) {
                // subkey binding revocation is not valid
                continue;
            }
            latestSubkeyRevocation = signature;
        }

        return latestSubkeyRevocation;
    }

    /**
     * Pick the, at validationDate latest, valid subkey binding signature for the given subkey.
     * This method might return null, if there is no subkey binding signature which is valid
     * at validationDate.
     *
     * @param keyRing key ring
     * @param subkey subkey
     * @param validationDate date of validation
     * @return most recent valid subkey binding signature
     */
    public static PGPSignature pickCurrentSubkeyBindingSignature(PGPKeyRing keyRing, PGPPublicKey subkey, Policy policy, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();
        if (primaryKey.getKeyID() == subkey.getKeyID()) {
            throw new IllegalArgumentException("Primary key cannot have subkey binding signature.");
        }

        List<PGPSignature> subkeyBindingSigs = getSortedSignaturesOfType(subkey, SignatureType.SUBKEY_BINDING);
        PGPSignature mostCurrentValidSig = null;

        for (PGPSignature signature : subkeyBindingSigs) {
            try {
                SignatureValidator.verifySubkeyBindingSignature(signature, primaryKey, subkey, policy, validationDate);
            } catch (SignatureValidationException validationException) {
                // Subkey binding sig is not valid
                continue;
            }
            mostCurrentValidSig = signature;
        }

        return mostCurrentValidSig;
    }

    /**
     * Pick the, at validationDate latest subkey binding signature for the given subkey.
     * This method might return an expired signature.
     * If a non-expired subkey binding signature exists, the latest non-expired yet already effective
     * subkey binding signature for the given subkey will be returned.
     *
     * @param keyRing key ring
     * @param subkey subkey
     * @param validationDate validationDate
     * @return subkey binding signature
     */
    public static PGPSignature pickLatestSubkeyBindingSignature(PGPKeyRing keyRing, PGPPublicKey subkey, Policy policy, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();
        if (primaryKey.getKeyID() == subkey.getKeyID()) {
            throw new IllegalArgumentException("Primary key cannot have subkey binding signature.");
        }

        List<PGPSignature> signatures = getSortedSignaturesOfType(subkey, SignatureType.SUBKEY_BINDING);
        PGPSignature latestSubkeyBinding = null;

        for (PGPSignature signature : signatures) {
            try {
                SignatureValidator.signatureIsOfType(SignatureType.SUBKEY_BINDING).verify(signature);
                SignatureValidator.signatureStructureIsAcceptable(primaryKey, policy).verify(signature);
                SignatureValidator.signatureIsAlreadyEffective(validationDate).verify(signature);
                // if the currently latest signature is not yet expired, check if the next candidate is not yet expired
                if (latestSubkeyBinding != null && !SignatureUtils.isSignatureExpired(latestSubkeyBinding, validationDate)) {
                    SignatureValidator.signatureIsNotYetExpired(validationDate).verify(signature);
                }
                SignatureValidator.correctSubkeyBindingSignature(primaryKey, subkey).verify(signature);
            } catch (SignatureValidationException e) {
                // Subkey binding sig is not valid
                continue;
            }
            latestSubkeyBinding = signature;
        }

        return latestSubkeyBinding;
    }

    /**
     * Return a list of all signatures of the given {@link SignatureType} on the given key, sorted using a
     * {@link SignatureCreationDateComparator}.
     *
     * The returned list will be sorted first by ascending signature creation time.
     *
     * @param key key
     * @param type type of signatures which shall be collected and sorted
     * @return sorted list of signatures
     */
    private static List<PGPSignature> getSortedSignaturesOfType(PGPPublicKey key, SignatureType type) {
        Iterator<PGPSignature> signaturesOfType = key.getSignaturesOfType(type.getCode());
        List<PGPSignature> signatureList = CollectionUtils.iteratorToList(signaturesOfType);
        Collections.sort(signatureList, new SignatureCreationDateComparator());
        return signatureList;
    }
}
