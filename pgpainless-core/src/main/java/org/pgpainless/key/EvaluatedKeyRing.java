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

import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.UserAttributePacket;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.util.NonEmptyList;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

public interface EvaluatedKeyRing {

    class EvaluatedSignature {
        private final PGPSignature signature;
        private final SignatureValidationException exception;

        PGPSignature getValidSignature() throws SignatureValidationException {
            if (getException() != null) {
                throw new SignatureValidationException("Signature is not valid.", getException());
            }
            return signature;
        }

        SignatureValidationException getException() {
            return exception;
        }

        public EvaluatedSignature(PGPSignature signature, SignatureValidationException exception) {
            this.signature = signature;
            this.exception = exception;
        }
    }

    /**
     * Return a {@link Map} of user-ids and associated user-id certification signatures.
     * Each map entry consists of a user-id and a {@link NonEmptyList} of associated certification signatures which
     * contains the latest non-revoking certification signature as its first element.
     *
     * @return map of user-ids and certifications
     */
    Map<String, NonEmptyList<PGPSignature>> getUserIdCertifications();

    /**
     * Return the latest user-id certification signature associated to the provided user-id.
     *
     * @param userId user-id
     * @return latest user-id certification signature
     * @throws IllegalArgumentException if the key doesn't have at least one certification signature for the
     * provided user-id.
     */
    default PGPSignature getUserIdCertification(String userId) {
        NonEmptyList<PGPSignature> userIdCerts = getUserIdCertifications().get(userId);
        if (userIdCerts == null) {
            throw new IllegalArgumentException("No user-id '" + userId + "' found on the key.");
        }
        return userIdCerts.get();
    }

    /**
     * Return a {@link Map} of user-ids and associated user-id revocation signatures.
     *
     * @return map of user-ids and revocations
     */
    Map<String, List<PGPSignature>> getUserIdRevocations();

    /**
     * Return the latest, hardest revocation signature for the passed in user-id.
     *
     * @param userId user-id
     * @return latest hardest revocation signature
     * @throws IllegalArgumentException if the key doesn't have at least one certification signature for the given user-id.
     */
    default PGPSignature getUserIdRevocation(String userId) {
        List<PGPSignature> userIdRevs = getUserIdRevocations().get(userId);
        if (userIdRevs == null) {
            throw new IllegalArgumentException("No user-id '" + userId + "' found on the key.");
        }
        return userIdRevs.isEmpty() ? null : userIdRevs.get(0);
    }

    default boolean isRevoked(String userId) {
        PGPSignature latestCertification = getUserIdCertification(userId);
        PGPSignature latestRevocation = getUserIdRevocation(userId);

        if (latestRevocation == null) {
            return false;
        }

        return latestRevocation.getCreationTime().after(latestCertification.getCreationTime())
                || SignatureUtils.isHardRevocation(latestRevocation);
    }

    /**
     * Return a {@link Map} of {@link UserAttributePacket UserAttributePackets} and associated certification signatures.
     * Each map entry consists of a {@link UserAttributePacket} and a {@link NonEmptyList} of associated certification
     * signatures which contains the latest non-revoking certification signtaure as its first element.
     *
     * @return map of user-attributes and certifications
     */
    Map<UserAttributePacket, NonEmptyList<PGPSignature>> getUserAttributeCertifications();

    /**
     * Return the latest certification signature for the provided {@link UserAttributePacket}.
     *
     * @param userAttribute user attribute
     * @return latest certification signature
     * @throws IllegalArgumentException if the key doesn't carry such user-attribute
     */
    default PGPSignature getUserAttributeCertification(UserAttributePacket userAttribute) {
        NonEmptyList<PGPSignature> userAttrCerts = getUserAttributeCertifications().get(userAttribute);
        if (userAttrCerts == null) {
            throw new IllegalArgumentException("No such user-attribute found on the key.");
        }
        return userAttrCerts.get();
    }

    Map<UserAttributePacket, List<PGPSignature>> getUserAttributeRevocations();

    default PGPSignature getUserAttributeRevocation(UserAttributePacket userAttribute) {
        List<PGPSignature> userAttrRevs = getUserAttributeRevocations().get(userAttribute);
        if (userAttrRevs == null) {
            throw new IllegalArgumentException("No such user-attribute found on the key.");
        }
        return userAttrRevs.isEmpty() ? null : userAttrRevs.get(0);
    }

    PGPSignature getSubkeyBinding(long subkeyId);

    PGPSignature getSubkeyRevocation(long subkeyId);

    default boolean isUserIdRevoked(String userId) {
        return getUserIdRevocation(userId) != null;
    }

    default boolean isSubkeyRevoked(long subkeyId) {
        return getSubkeyRevocation(subkeyId) != null;
    }

    default @Nullable List<KeyFlag> getUserIdKeyFlags(String userId) {
        PGPSignature signature = getUserIdCertification(userId);
        return SignatureSubpacketsUtil.parseKeyFlags(signature);
    }
}
