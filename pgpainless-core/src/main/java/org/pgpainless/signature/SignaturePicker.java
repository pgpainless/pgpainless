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

import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
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
public class SignaturePicker {

    /**
     * Pick the most current (at the time of evaluation) key revocation signature.
     * If there is a hard revocation signature, it is picked, regardless of expiration or creation time.
     *
     * @param keyRing key ring
     * @return most recent, valid key revocation signature
     */
    public static PGPSignature pickCurrentRevocationSelfSignature(PGPKeyRing keyRing, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();

        List<PGPSignature> signatures = getSortedSignaturesOfType(primaryKey, SignatureType.KEY_REVOCATION);
        PGPSignature mostCurrentValidSig = null;

        for (PGPSignature signature : signatures) {
            if (!SelectSignatureFromKey.isWellFormed().accept(signature, primaryKey, keyRing)) {
                // Signature is not well-formed. Reject
                continue;
            }

            if (!SelectSignatureFromKey.isCreatedBy(keyRing.getPublicKey()).accept(signature, primaryKey, keyRing)) {
                // Revocation signature was not created by primary key
                continue;
            }

            RevocationReason reason = SignatureSubpacketsUtil.getRevocationReason(signature);
            if (reason != null && !RevocationAttributes.Reason.isHardRevocation(reason.getRevocationReason())) {
                // reason code states soft revocation
                if (!SelectSignatureFromKey.isValidAt(validationDate).accept(signature, primaryKey, keyRing)) {
                    // Soft revocation is either expired or not yet valid
                    continue;
                }
            }

            if (!SelectSignatureFromKey.isValidKeyRevocationSignature(primaryKey).accept(signature, primaryKey, keyRing)) {
                // sig does not check out
                continue;
            }

            mostCurrentValidSig = signature;
        }

        return mostCurrentValidSig;
    }

    /**
     * Pick the current direct key self-signature on the primary key.
     * @param keyRing key ring
     * @param validationDate validation date
     * @return direct-key self-signature
     */
    public static PGPSignature pickCurrentDirectKeySelfSignature(PGPKeyRing keyRing, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();
        return pickCurrentDirectKeySignature(primaryKey, primaryKey, keyRing, validationDate);
    }

    /**
     * Pick the current direct-key signature made by the signing key on the signed key.
     *
     * @param signingKey key that created the signature
     * @param signedKey key that carries the signature
     * @param keyRing key ring
     * @param validationDate validation date
     * @return direct key sig
     */
    public static PGPSignature pickCurrentDirectKeySignature(PGPPublicKey signingKey, PGPPublicKey signedKey, PGPKeyRing keyRing, Date validationDate) {
        List<PGPSignature> directKeySignatures = getSortedSignaturesOfType(signedKey, SignatureType.DIRECT_KEY);

        PGPSignature mostRecentDirectKeySigBySigningKey = null;
        for (PGPSignature signature : directKeySignatures) {
            if (!SelectSignatureFromKey.isWellFormed().accept(signature, signingKey, keyRing)) {
                // signature is not well formed
                continue;
            }

            if (!SelectSignatureFromKey.isValidAt(validationDate).accept(signature, signedKey, keyRing)) {
                // Signature is either expired or not yet valid
                continue;
            }

            if (!SelectSignatureFromKey.isValidDirectKeySignature(signingKey, signedKey).accept(signature, signedKey, keyRing)) {
                // signature does not check out.
                continue;
            }
            mostRecentDirectKeySigBySigningKey = signature;
        }

        return mostRecentDirectKeySigBySigningKey;
    }

    /**
     * Pick the most recent user-id revocation signature.
     *
     * @param keyRing key ring
     * @param userId user-Id that gets revoked
     * @param validationDate validation date
     * @return revocation signature
     */
    public static PGPSignature pickCurrentUserIdRevocationSignature(PGPKeyRing keyRing, String userId, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();

        Iterator<PGPSignature> certificationRevocations = primaryKey.getSignaturesOfType(SignatureType.CERTIFICATION_REVOCATION.getCode());
        List<PGPSignature> signatures = CollectionUtils.iteratorToList(certificationRevocations);
        Collections.sort(signatures, new SignatureCreationDateComparator());

        PGPSignature mostRecentUserIdRevocation = null;
        for (PGPSignature signature : signatures) {
            if (!SelectSignatureFromKey.isWellFormed().accept(signature, primaryKey, keyRing)) {
                // Sig is not well formed.
                continue;
            }

            RevocationReason reason = SignatureSubpacketsUtil.getRevocationReason(signature);
            if (reason != null && !RevocationAttributes.Reason.isHardRevocation(reason.getRevocationReason())) {
                // reason code states soft revocation
                if (!SelectSignatureFromKey.isValidAt(validationDate).accept(signature, primaryKey, keyRing)) {
                    // Soft revocation is either expired or not yet valid
                    continue;
                }
            }

            if (!SelectSignatureFromKey.isValidCertificationRevocationSignature(primaryKey, userId)
                    .accept(signature, primaryKey, keyRing)) {
                // sig does not check out for userid
                continue;
            }

            mostRecentUserIdRevocation = signature;
        }

        return mostRecentUserIdRevocation;
    }

    /**
     * Pick the most current certification self-signature for the given user-id.
     *
     * @param keyRing keyring
     * @param userId userid
     * @param validationDate validation date
     * @return user-id certification
     */
    public static PGPSignature pickCurrentUserIdCertificationSignature(PGPKeyRing keyRing, String userId, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();

        Iterator<PGPSignature> userIdSigIterator = primaryKey.getSignaturesForID(userId);
        List<PGPSignature> signatures = CollectionUtils.iteratorToList(userIdSigIterator);
        Collections.sort(signatures, new SignatureCreationDateComparator());

        PGPSignature mostRecentUserIdCertification = null;
        for (PGPSignature signature : signatures) {
            if (!SelectSignatureFromKey.isWellFormed().accept(signature, primaryKey, keyRing)) {
                // Sig not well formed
                continue;
            }

            if (!SelectSignatureFromKey.isValidAt(validationDate).accept(signature, primaryKey, keyRing)) {
                // Sig is either expired or not valid yet
                continue;
            }

            if (!SelectSignatureFromKey.isValidSignatureOnUserId(userId, primaryKey).accept(signature, primaryKey, keyRing)) {
                // Sig does not check out
                continue;
            }

            mostRecentUserIdCertification = signature;
        }

        return mostRecentUserIdCertification;
    }

    /**
     * Return the current subkey binding revocation signature for the given subkey.
     *
     * @param keyRing keyring
     * @param subkey subkey
     * @param validationDate validation date
     * @return subkey revocation signature
     */
    public static PGPSignature pickCurrentSubkeyBindingRevocationSignature(PGPKeyRing keyRing, PGPPublicKey subkey, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();
        if (primaryKey.getKeyID() == subkey.getKeyID()) {
            throw new IllegalArgumentException("Primary key cannot have subkey binding revocations.");
        }

        List<PGPSignature> subkeyRevocationSigs = getSortedSignaturesOfType(subkey, SignatureType.SUBKEY_BINDING);
        PGPSignature mostRecentSubkeyRevocation = null;

        for (PGPSignature signature : subkeyRevocationSigs) {
            if (!SelectSignatureFromKey.isWellFormed().accept(signature, primaryKey, keyRing)) {
                // Signature is not well formed
                continue;
            }

            RevocationReason reason = SignatureSubpacketsUtil.getRevocationReason(signature);
            if (reason != null && !RevocationAttributes.Reason.isHardRevocation(reason.getRevocationReason())) {
                // reason code states soft revocation
                if (!SelectSignatureFromKey.isValidAt(validationDate).accept(signature, primaryKey, keyRing)) {
                    // Soft revocation is either expired or not yet valid
                    continue;
                }
            }

            if (!SelectSignatureFromKey.isValidSubkeyRevocationSignature().accept(signature, subkey, keyRing)) {
                // Signature does not check out
                continue;
            }
            mostRecentSubkeyRevocation = signature;
        }

        return mostRecentSubkeyRevocation;
    }

    /**
     * Return the (at the time of validation) most recent, valid subkey binding signature
     * made by the primary key of the key ring on the subkey.
     *
     * @param keyRing key ring
     * @param subkey subkey
     * @param validationDate date of validation
     * @return most recent valid subkey binding signature
     */
    public static PGPSignature pickCurrentSubkeyBindingSignature(PGPKeyRing keyRing, PGPPublicKey subkey, Date validationDate) {
        PGPPublicKey primaryKey = keyRing.getPublicKey();
        if (primaryKey.getKeyID() == subkey.getKeyID()) {
            throw new IllegalArgumentException("Primary key cannot have subkey binding signature.");
        }

        List<PGPSignature> subkeyBindingSigs = getSortedSignaturesOfType(subkey, SignatureType.SUBKEY_BINDING);
        PGPSignature mostCurrentValidSig = null;

        for (PGPSignature signature : subkeyBindingSigs) {
            // has hashed creation time, does not predate signing key creation date
            if (!SelectSignatureFromKey.isWellFormed().accept(signature, primaryKey, keyRing)) {
                // Signature is not well-formed. Reject.
                continue;
            }

            SignatureCreationTime creationTime = SignatureSubpacketsUtil.getSignatureCreationTime(signature);
            if (creationTime.getTime().after(validationDate)) {
                // signature is not yet valid
                continue;
            }

            if (SignatureUtils.isSignatureExpired(signature, validationDate)) {
                // Signature is expired
                continue;
            }

            if (!SelectSignatureFromKey.isValidSubkeyBindingSignature(primaryKey, subkey)
                    .accept(signature, subkey, keyRing)) {
                // Invalid subkey binding signature
                continue;
            }

            mostCurrentValidSig = signature;
        }

        return mostCurrentValidSig;
    }

    private static List<PGPSignature> getSortedSignaturesOfType(PGPPublicKey key, SignatureType type) {
        Iterator<PGPSignature> signaturesOfType = key.getSignaturesOfType(type.getCode());
        List<PGPSignature> signatureList = CollectionUtils.iteratorToList(signaturesOfType);
        Collections.sort(signatureList, new SignatureCreationDateComparator());
        return signatureList;
    }
}
