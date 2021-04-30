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
package org.pgpainless.key;

import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.SelectSignatureFromKey;
import org.pgpainless.signature.SignatureCreationDateComparator;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.signature.SignatureValidator;
import org.pgpainless.util.CollectionUtils;

public class KeyRingValidator {

    private static final Logger LOGGER = Logger.getLogger(KeyRingValidator.class.getName());

    public static <R extends PGPKeyRing> R validate(R keyRing, Policy policy) {
        try {
            return validate(keyRing, policy, policy.getSignatureValidationDate());
        } catch (PGPException e) {
            return null;
        }
    }

    public static <R extends PGPKeyRing> R validate(R keyRing, Policy policy, Date validationDate) throws PGPException {
        return getKeyRingAtDate(keyRing, policy, validationDate);
    }

    private static <R extends PGPKeyRing> R getKeyRingAtDate(R keyRing, Policy policy, Date validationDate) throws PGPException {
        PGPPublicKey primaryKey = keyRing.getPublicKey();
        primaryKey = evaluatePrimaryKey(primaryKey, policy, validationDate);
        if (keyRing instanceof PGPPublicKeyRing) {
            PGPPublicKeyRing publicKeys = (PGPPublicKeyRing) keyRing;
            publicKeys = PGPPublicKeyRing.insertPublicKey(publicKeys, primaryKey);
            keyRing = (R) publicKeys;
        }

        return keyRing;
    }

    private static PGPPublicKey evaluatePrimaryKey(PGPPublicKey primaryKey, Policy policy, Date validationDate) throws PGPException {

        PGPPublicKey blank = new PGPPublicKey(primaryKey.getPublicKeyPacket(), ImplementationFactory.getInstance().getKeyFingerprintCalculator());

        Iterator<PGPSignature> directKeyIterator = primaryKey.getSignaturesOfType(SignatureType.DIRECT_KEY.getCode());
        List<PGPSignature> directKeyCertifications = CollectionUtils.iteratorToList(directKeyIterator);
        Collections.sort(directKeyCertifications, new SignatureCreationDateComparator(SignatureCreationDateComparator.Order.NEW_TO_OLD));
        for (PGPSignature signature : directKeyCertifications) {
            try {
                if (SignatureValidator.verifyDirectKeySignature(signature, blank, policy, validationDate)) {
                    blank = PGPPublicKey.addCertification(blank, signature);
                }
            } catch (SignatureValidationException e) {
                LOGGER.log(Level.INFO, "Rejecting direct key signature", e);
            }
        }

        Iterator<PGPSignature> revocationIterator = primaryKey.getSignaturesOfType(SignatureType.KEY_REVOCATION.getCode());
        List<PGPSignature> directKeyRevocations = CollectionUtils.iteratorToList(revocationIterator);
        Collections.sort(directKeyRevocations, new SignatureCreationDateComparator(SignatureCreationDateComparator.Order.NEW_TO_OLD));
        for (PGPSignature signature : directKeyRevocations) {
            try {
                if (SignatureValidator.verifyKeyRevocationSignature(signature, primaryKey, policy, validationDate)) {
                    blank = PGPPublicKey.addCertification(blank, signature);
                }
            } catch (SignatureValidationException e) {
                LOGGER.log(Level.INFO, "Rejecting key revocation signature", e);
            }
        }

        Iterator<String> userIdIterator = primaryKey.getUserIDs();
        while (userIdIterator.hasNext()) {
            String userId = userIdIterator.next();
            Iterator<PGPSignature> userIdSigs = primaryKey.getSignaturesForID(userId);
            List<PGPSignature> signatures = CollectionUtils.iteratorToList(userIdSigs);
            Collections.sort(signatures, new SignatureCreationDateComparator(SignatureCreationDateComparator.Order.NEW_TO_OLD));
            for (PGPSignature signature : signatures) {
                try {
                    if (SignatureType.valueOf(signature.getSignatureType()) == SignatureType.CERTIFICATION_REVOCATION) {
                        if (SignatureValidator.verifyUserIdRevocation(userId, signature, primaryKey, policy, validationDate)) {
                            blank = PGPPublicKey.addCertification(blank, userId, signature);
                        }
                    } else {
                        if (SignatureValidator.verifyUserIdCertification(userId, signature, primaryKey, policy, validationDate)) {
                            blank = PGPPublicKey.addCertification(blank, userId, signature);
                        }
                    }
                } catch (SignatureValidationException e) {
                    LOGGER.log(Level.INFO, "Rejecting user-id certification for user-id " + userId, e);
                }
            }
        }

        Iterator<PGPUserAttributeSubpacketVector> userAttributes = primaryKey.getUserAttributes();
        while (userAttributes.hasNext()) {
            PGPUserAttributeSubpacketVector userAttribute = userAttributes.next();
            Iterator<PGPSignature> userAttributeSignatureIterator = primaryKey.getSignaturesForUserAttribute(userAttribute);
            while (userAttributeSignatureIterator.hasNext()) {
                PGPSignature signature = userAttributeSignatureIterator.next();
                try {
                    if (SignatureType.valueOf(signature.getSignatureType()) == SignatureType.CERTIFICATION_REVOCATION) {
                        if (SignatureValidator.verifyUserAttributesRevocation(userAttribute, signature, primaryKey, policy, validationDate)) {
                            blank = PGPPublicKey.addCertification(blank, userAttribute, signature);
                        }
                    } else {
                        if (SignatureValidator.verifyUserAttributesCertification(userAttribute, signature, primaryKey, policy, validationDate)) {
                            blank = PGPPublicKey.addCertification(blank, userAttribute, signature);
                        }
                    }
                } catch (SignatureValidationException e) {
                    LOGGER.log(Level.INFO, "Rejecting user-attribute signature", e);
                }
            }
        }

        return blank;
    }

    public static <R extends PGPKeyRing> R getKeyRingAtDate(R keyRing, KeyRingInfo info) {
        Iterator<PGPPublicKey> iterator = keyRing.getPublicKeys();
        while (iterator.hasNext()) {
            PGPPublicKey publicKey = iterator.next();
            if (publicKey.isMasterKey()) {
                keyRing = assessPrimaryKeyAtDate(publicKey, keyRing, info);
            } else {
                keyRing = assessSubkeyAtDate(publicKey, keyRing, info);
            }
        }
        return keyRing;
    }

    private static <R extends PGPKeyRing> R assessPrimaryKeyAtDate(PGPPublicKey primaryKey, PGPKeyRing keyRing, KeyRingInfo info) {
        if (!primaryKey.isMasterKey()) {
            throw new IllegalArgumentException("Passed in key is not a primary key");
        }

        // Direct Key Signatures
        PGPSignature latestSelfSig = info.getCurrentDirectKeySelfSignature();
        PGPSignature latestSelfRevocation = info.getRevocationSelfSignature();


        // User-ID certifications
        Iterator<String> userIdIterator = primaryKey.getUserIDs();
        while (userIdIterator.hasNext()) {
            String userId = userIdIterator.next();
            boolean isUserIdBound = false;
            Iterator<PGPSignature> userIdSigIterator = primaryKey.getSignaturesForID(userId);
            while (userIdSigIterator.hasNext()) {
                PGPSignature userIdSig = userIdSigIterator.next();
                if (!SelectSignatureFromKey.isValidSignatureOnUserId(userId, primaryKey)
                        .accept(userIdSig, primaryKey, keyRing)) {
                    primaryKey = PGPPublicKey.removeCertification(primaryKey, userId, userIdSig);
                    continue;
                }
                isUserIdBound = true;
            }
            if (!isUserIdBound) {
                primaryKey = PGPPublicKey.removeCertification(primaryKey, userId);
            }
        }

        // Revocations
        Iterator<PGPSignature> revocationSignatures = primaryKey.getSignaturesOfType(SignatureType.KEY_REVOCATION.getCode());
        while (revocationSignatures.hasNext()) {
            PGPSignature revocationSig = revocationSignatures.next();
            if (!SelectSignatureFromKey.isValidKeyRevocationSignature(primaryKey)
                    .accept(revocationSig, primaryKey, keyRing)) {
                primaryKey = PGPPublicKey.removeCertification(primaryKey, revocationSig);
            }
        }

        return (R) replacePublicKey(keyRing, primaryKey);
    }

    private static <R extends PGPKeyRing> R assessSubkeyAtDate(PGPPublicKey subkey, PGPKeyRing keyRing, KeyRingInfo info) {
        if (subkey.isMasterKey()) {
            throw new IllegalArgumentException("Passed in key is not a subkey");
        }

        // Subkey binding sigs
        Iterator<PGPSignature> subkeyBindingSigIterator = subkey.getSignaturesOfType(SignatureType.SUBKEY_BINDING.getCode());
        while (subkeyBindingSigIterator.hasNext()) {
            PGPSignature signature = subkeyBindingSigIterator.next();
            if (!SelectSignatureFromKey.isValidSubkeyBindingSignature(keyRing.getPublicKey(), subkey)
                    .accept(signature, subkey, keyRing)) {
                subkey = PGPPublicKey.removeCertification(subkey, signature);
            }
        }

        // Subkey revocation sigs
        Iterator<PGPSignature> revocationSigIterator = subkey.getSignaturesOfType(SignatureType.SUBKEY_REVOCATION.getCode());
        while (revocationSigIterator.hasNext()) {
            PGPSignature signature = revocationSigIterator.next();
            if (!SelectSignatureFromKey.isValidSubkeyRevocationSignature().accept(signature, subkey, keyRing)) {
                subkey = PGPPublicKey.removeCertification(subkey, signature);
            }
        }

        Iterator<PGPSignature> directKeySigIterator = subkey.getSignaturesOfType(SignatureType.DIRECT_KEY.getCode());
        while (directKeySigIterator.hasNext()) {
            PGPSignature signature = directKeySigIterator.next();
            PGPPublicKey creator = keyRing.getPublicKey(signature.getKeyID());
            if (creator == null) {
                // remove external signature
                subkey = PGPPublicKey.removeCertification(subkey, signature);
                continue;
            }

            if (!SelectSignatureFromKey.isValidDirectKeySignature(creator, subkey)
                    .accept(signature, subkey, keyRing)) {
                subkey = PGPPublicKey.removeCertification(subkey, signature);
            }
        }

        return (R) replacePublicKey(keyRing, subkey);
    }

    private static PGPKeyRing replacePublicKey(PGPKeyRing keyRing, PGPPublicKey publicKey) {
        if (keyRing instanceof PGPPublicKeyRing) {
            keyRing = PGPPublicKeyRing.insertPublicKey((PGPPublicKeyRing) keyRing, publicKey);
        } else if (keyRing instanceof PGPSecretKeyRing) {
            PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) keyRing;
            PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeys);
            publicKeys = PGPPublicKeyRing.insertPublicKey(publicKeys, publicKey);
            secretKeys = PGPSecretKeyRing.replacePublicKeys(secretKeys, publicKeys);
            keyRing = secretKeys;
        }
        return keyRing;
    }
}
