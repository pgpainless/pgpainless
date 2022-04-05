// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.consumer.SignatureCreationDateComparator;
import org.pgpainless.signature.consumer.SignatureVerifier;
import org.pgpainless.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class KeyRingValidator {

    private KeyRingValidator() {

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyRingValidator.class);

    public static <R extends PGPKeyRing> R validate(R keyRing, Policy policy) {
        try {
            return validate(keyRing, policy, new Date());
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
                if (SignatureVerifier.verifyDirectKeySignature(signature, blank, policy, validationDate)) {
                    blank = PGPPublicKey.addCertification(blank, signature);
                }
            } catch (SignatureValidationException e) {
                LOGGER.debug("Rejecting direct key signature: {}", e.getMessage(), e);
            }
        }

        Iterator<PGPSignature> revocationIterator = primaryKey.getSignaturesOfType(SignatureType.KEY_REVOCATION.getCode());
        List<PGPSignature> directKeyRevocations = CollectionUtils.iteratorToList(revocationIterator);
        Collections.sort(directKeyRevocations, new SignatureCreationDateComparator(SignatureCreationDateComparator.Order.NEW_TO_OLD));
        for (PGPSignature signature : directKeyRevocations) {
            try {
                if (SignatureVerifier.verifyKeyRevocationSignature(signature, primaryKey, policy, validationDate)) {
                    blank = PGPPublicKey.addCertification(blank, signature);
                }
            } catch (SignatureValidationException e) {
                LOGGER.debug("Rejecting key revocation signature: {}", e.getMessage(), e);
            }
        }

        Iterator<String> userIdIterator = primaryKey.getUserIDs();
        while (userIdIterator.hasNext()) {
            String userId = userIdIterator.next();
            Iterator<PGPSignature> userIdSigs = primaryKey.getSignaturesForID(userId);
            List<PGPSignature> signatures = CollectionUtils.iteratorToList(userIdSigs);
            Collections.sort(signatures, new SignatureCreationDateComparator(SignatureCreationDateComparator.Order.NEW_TO_OLD));
            for (PGPSignature signature : signatures) {
                if (signature.getKeyID() != primaryKey.getKeyID()) {
                    // Signature was not made by primary key
                    continue;
                }
                try {
                    if (SignatureType.valueOf(signature.getSignatureType()) == SignatureType.CERTIFICATION_REVOCATION) {
                        if (SignatureVerifier.verifyUserIdRevocation(userId, signature, primaryKey, policy, validationDate)) {
                            blank = PGPPublicKey.addCertification(blank, userId, signature);
                        }
                    } else {
                        if (SignatureVerifier.verifyUserIdCertification(userId, signature, primaryKey, policy, validationDate)) {
                            blank = PGPPublicKey.addCertification(blank, userId, signature);
                        }
                    }
                } catch (SignatureValidationException e) {
                    LOGGER.debug("Rejecting user-id certification for user-id {}: {}", userId, e.getMessage(), e);
                }
            }
        }

        Iterator<PGPUserAttributeSubpacketVector> userAttributes = primaryKey.getUserAttributes();
        while (userAttributes.hasNext()) {
            PGPUserAttributeSubpacketVector userAttribute = userAttributes.next();
            Iterator<PGPSignature> userAttributeSignatureIterator = primaryKey.getSignaturesForUserAttribute(userAttribute);
            while (userAttributeSignatureIterator.hasNext()) {
                PGPSignature signature = userAttributeSignatureIterator.next();
                if (signature.getKeyID() != primaryKey.getKeyID()) {
                    // Signature was not made by primary key
                    continue;
                }
                try {
                    if (SignatureType.valueOf(signature.getSignatureType()) == SignatureType.CERTIFICATION_REVOCATION) {
                        if (SignatureVerifier.verifyUserAttributesRevocation(userAttribute, signature, primaryKey, policy, validationDate)) {
                            blank = PGPPublicKey.addCertification(blank, userAttribute, signature);
                        }
                    } else {
                        if (SignatureVerifier.verifyUserAttributesCertification(userAttribute, signature, primaryKey, policy, validationDate)) {
                            blank = PGPPublicKey.addCertification(blank, userAttribute, signature);
                        }
                    }
                } catch (SignatureValidationException e) {
                    LOGGER.debug("Rejecting user-attribute signature: {}", e.getMessage(), e);
                }
            }
        }

        return blank;
    }

}
