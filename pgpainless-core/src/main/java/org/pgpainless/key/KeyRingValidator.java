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
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.SignatureCreationDateComparator;
import org.pgpainless.signature.SignatureValidator;
import org.pgpainless.util.CollectionUtils;

public class KeyRingValidator {

    private static final Logger LOGGER = Logger.getLogger(KeyRingValidator.class.getName());

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
                    LOGGER.log(Level.FINE, "Rejecting user-id certification for user-id " + userId, e);
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

}
