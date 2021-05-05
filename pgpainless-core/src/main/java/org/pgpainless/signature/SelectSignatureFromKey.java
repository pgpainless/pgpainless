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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

/**
 * Utility class to select signatures from keys based on certain criteria.
 * This abstract class provides a method {@link #accept(PGPSignature, PGPPublicKey, PGPKeyRing)} which shall only
 * return true if the provided signature is acceptable regarding the implementations selection criteria.
 *
 * The idea is to create an implementation of the class for each criterion, so that those criteria can be
 * composed to create complex validity checks.
 */
public abstract class SelectSignatureFromKey {

    private static final Logger LOGGER = Logger.getLogger(SelectSignatureFromKey.class.getName());

    public abstract boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing);

    public List<PGPSignature> select(List<PGPSignature> signatures, PGPPublicKey key, PGPKeyRing keyRing) {
        List<PGPSignature> selected = new ArrayList<>();
        for (PGPSignature signature : signatures) {
            if (accept(signature, key, keyRing)) {
                selected.add(signature);
            }
        }
        return selected;
    }

    /**
     * Criterion that checks if the signature is valid at the validation date.
     * A signature is not valid if it was created after the validation date, or if it is expired at the validation date.
     *
     * creationTime &le; validationDate &lt; expirationDate.
     *
     * @param validationDate validation date
     * @return criterion implementation
     */
    public static SelectSignatureFromKey isValidAt(Date validationDate) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                Date expirationDate = SignatureUtils.getSignatureExpirationDate(signature);
                return !signature.getCreationTime().after(validationDate) && (expirationDate == null || expirationDate.after(validationDate));
            }
        };
    }

    /**
     * Criterion that checks if the provided signature is a valid subkey binding signature.
     *
     * A signature is only a valid subkey binding signature if it is of type {@link SignatureType#SUBKEY_BINDING},
     * if it was created by the primary key, and - if the subkey is capable of signing - it contains a valid
     * primary key binding signature.
     *
     * @param primaryKey primary key
     * @param subkey subkey
     * @return criterion to validate binding signatures
     */
    public static SelectSignatureFromKey isValidSubkeyBindingSignature(PGPPublicKey primaryKey, PGPPublicKey subkey) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {

                if (!isOfType(SignatureType.SUBKEY_BINDING).accept(signature, key, keyRing)) {
                    return false;
                }

                if (signature.getKeyID() != primaryKey.getKeyID()) {
                    return false;
                }

                if (!isSigNotExpired().accept(signature, subkey, keyRing)) {
                    LOGGER.log(Level.INFO, "Subkey binding signature expired.");
                    return false;
                }

                // Check signature correctness
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), primaryKey);
                    boolean subkeyBindingSigValid = signature.verifyCertification(primaryKey, subkey);
                    if (!subkeyBindingSigValid) {
                        return false;
                    }
                } catch (PGPException e) {
                    LOGGER.log(Level.INFO, "Verification of subkey binding signature failed.", e);
                    return false;
                }

                List<KeyFlag> flags = KeyFlag.fromBitmask(signature.getHashedSubPackets().getKeyFlags());
                boolean isSigningKey = flags.contains(KeyFlag.SIGN_DATA) || flags.contains(KeyFlag.CERTIFY_OTHER);

                if (isSigningKey && !hasValidPrimaryKeyBindingSignatureSubpacket(subkey, primaryKey)
                        .accept(signature, subkey, keyRing)) {
                    LOGGER.log(Level.INFO, "Subkey binding signature on signing key does not carry valid primary key binding signature.");
                    return false;
                }
                return true;
            }
        };
    }

    /**
     * Criterion that checks if a primary key binding signature is valid.
     *
     * @param subkey subkey
     * @param primaryKey primary key
     * @return criterion to validate primary key binding signatures
     */
    public static SelectSignatureFromKey isValidPrimaryKeyBindingSignature(PGPPublicKey subkey, PGPPublicKey primaryKey) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {

                if (!isVersion4Signature().accept(signature, key, keyRing)) {
                    return false;
                }

                if (!isOfType(SignatureType.PRIMARYKEY_BINDING).accept(signature, key, keyRing)) {
                    return false;
                }

                if (signature.getKeyID() != subkey.getKeyID()) {
                    return false;
                }

                if (!isSigNotExpired().accept(signature, primaryKey, keyRing)) {
                    LOGGER.log(Level.INFO, "Primary key binding signature expired.");
                    return false;
                }

                // Check signature correctness
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), subkey);
                    return signature.verifyCertification(primaryKey, subkey);
                } catch (PGPException e) {
                    return false;
                }
            }
        };
    }

    /**
     * Criterion that checks if a signature has an embedded valid primary key binding signature.
     * @param subkey subkey
     * @param primaryKey primary key
     * @return criterion
     */
    public static SelectSignatureFromKey hasValidPrimaryKeyBindingSignatureSubpacket(PGPPublicKey subkey, PGPPublicKey primaryKey) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                try {
                    PGPSignatureList embeddedSignatures = SignatureSubpacketsUtil.getEmbeddedSignature(signature);
                    if (embeddedSignatures != null) {
                        for (PGPSignature embeddedSignature : embeddedSignatures) {
                            if (isValidPrimaryKeyBindingSignature(subkey, primaryKey).accept(embeddedSignature, subkey, keyRing)) {
                                return true;
                            }
                        }
                    }
                } catch (PGPException e) {
                    LOGGER.log(Level.WARNING, "Cannot parse embedded signatures:", e);
                }
                return false;
            }
        };
    }

    /**
     * Criterion that checks if a signature is a valid v4 direct-key signature.
     * Note: This method does not check expiration.
     *
     * @param signer signing key
     * @param signee signed key
     * @return criterion
     */
    public static SelectSignatureFromKey isValidDirectKeySignature(PGPPublicKey signer, PGPPublicKey signee) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                if (!isVersion4Signature().accept(signature, key, keyRing)) {
                    return false;
                }

                if (!isOfType(SignatureType.DIRECT_KEY).accept(signature, key, keyRing)) {
                    return false;
                }

                // Check signature correctness
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signer);
                    return signature.verifyCertification(signee);
                } catch (PGPException e) {
                    return false;
                }
            }
        };
    }

    /**
     * Criterion that checks if a signature is a valid key revocation signature.
     *
     * @param key primary key
     * @return criterion
     */
    public static SelectSignatureFromKey isValidKeyRevocationSignature(PGPPublicKey key) {
        return and(
                isVersion4Signature(),
                isOfType(SignatureType.KEY_REVOCATION),
                isCreatedBy(key),
                isWellFormed(),
                doesNotPredateKeyCreationDate(key),
                isVerifyingSignatureOnKey(key, key)
        );
    }

    /**
     * Criterion that only accepts valid subkey revocation signatures.
     *
     * @return criterion
     */
    public static SelectSignatureFromKey isValidSubkeyRevocationSignature() {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return isValidSubkeyRevocationSignature(key, keyRing.getPublicKey())
                        .accept(signature, key, keyRing);
            }
        };
    }

    /**
     * Criterion that only accepts valid subkey revocation signatures.
     *
     * @param subkey subkey
     * @param primaryKey primary key
     * @return criterion
     */
    public static SelectSignatureFromKey isValidSubkeyRevocationSignature(PGPPublicKey subkey, PGPPublicKey primaryKey) {
        return SelectSignatureFromKey.and(
                isVersion4Signature(),
                isOfType(SignatureType.SUBKEY_REVOCATION),
                isCreatedBy(primaryKey),
                isVerifyingSignatureOnKeys(primaryKey, subkey, primaryKey)
        );
    }

    /**
     * Criterion that only accepts signatures which are valid user-id revocations.
     *
     * @param revoker signing key
     * @param userId user id
     * @return criterion
     */
    public static SelectSignatureFromKey isValidCertificationRevocationSignature(PGPPublicKey revoker, String userId) {
        return and(
                isVersion4Signature(),
                isCreatedBy(revoker),
                isOfType(SignatureType.CERTIFICATION_REVOCATION),
                isValidSignatureOnUserId(userId, revoker)
        );
    }

    /**
     * Criterion that only accepts signatures which are valid signatures over a user-id.
     * This method only checks signature correctness, not expiry etc.
     *
     * @param userId user-id
     * @param signingKey signing key
     * @return criterion
     */
    public static SelectSignatureFromKey isValidSignatureOnUserId(String userId, PGPPublicKey signingKey) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signingKey);
                    return signature.verifyCertification(userId, key);
                } catch (PGPException e) {
                    LOGGER.log(Level.INFO, "Verification of signature on userID " + userId + " failed.", e);
                    return false;
                }
            }
        };
    }

    /**
     * Criterion that only accepts signatures which are valid signatures over a key.
     * This method only checks signature correctness, not expiry etc.
     *
     * @param target signed key
     * @param signer signing key
     * @return criterion
     */
    public static SelectSignatureFromKey isVerifyingSignatureOnKey(PGPPublicKey target, PGPPublicKey signer) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signer);
                    boolean valid = signature.verifyCertification(target);
                    return valid;
                } catch (PGPException e) {
                    LOGGER.log(Level.INFO, "Signature verification failed.", e);
                    return false;
                }
            }
        };
    }

    /**
     * Criterion that only accepts signatures which are correct binding signatures.
     * This method only checks signature correctness, not expiry etc.
     *
     * @param primaryKey primary key
     * @param subkey subkey
     * @param signingKey signing key (either primary, or subkey)
     * @return criterion
     */
    public static SelectSignatureFromKey isVerifyingSignatureOnKeys(PGPPublicKey primaryKey, PGPPublicKey subkey, PGPPublicKey signingKey) {
        if (signingKey.getKeyID() != primaryKey.getKeyID() && signingKey.getKeyID() != subkey.getKeyID()) {
            throw new IllegalArgumentException("Signing key MUST be either the primary or subkey.");
        }
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signingKey);
                    return signature.verifyCertification(primaryKey, subkey);
                } catch (PGPException e) {
                    LOGGER.log(Level.INFO, "Verification of " + SignatureType.valueOf(signature.getSignatureType()) + " signature failed.", e);
                    return false;
                }
            }
        };
    }

    /**
     * Criterion that only accepts certification signatures.
     *
     * Those are signature of the following types:
     * - {@link SignatureType#NO_CERTIFICATION},
     * - {@link SignatureType#CASUAL_CERTIFICATION},
     * - {@link SignatureType#GENERIC_CERTIFICATION},
     * - {@link SignatureType#POSITIVE_CERTIFICATION}.
     *
     * @return criterion
     */
    public static SelectSignatureFromKey isCertification() {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.isCertification();
            }
        };
    }

    /**
     * Criterion that only accepts "well formed" signatures.
     * A signature is "well formed", iff it has a creation time subpacket and if it does not predate
     * its creating keys creation time.
     *
     * @return criterion
     */
    public static SelectSignatureFromKey isWellFormed() {
        return and(
                hasCreationTimeSubpacket(),
                doesNotPredateKeyCreationDate()
        );
    }

    /**
     * Criterion that only accepts v4 signatures.
     *
     * @return criterion
     */
    public static SelectSignatureFromKey isVersion4Signature() {
        return isVersion(4);
    }

    /**
     * Criterion that only accepts signatures which carry a creation time subpacket.
     * According to the RFC, all signatures are required to have such a subpacket.
     *
     * @return criterion
     */
    public static SelectSignatureFromKey hasCreationTimeSubpacket() {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.getHashedSubPackets().getSignatureCreationTime() != null;
            }
        };
    }

    /**
     * Criterion that only accepts signatures that were created by the provided key.
     *
     * @param publicKey public key of the creation key pair
     * @return criterion
     */
    public static SelectSignatureFromKey isCreatedBy(PGPPublicKey publicKey) {
        return isCreatedBy(publicKey.getKeyID());
    }

    /**
     * Criterion that only accepts signatures which were created by the public key with the provided key id.
     *
     * @param keyId key id
     * @return criterion
     */
    public static SelectSignatureFromKey isCreatedBy(long keyId) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.getKeyID() == keyId;
            }
        };
    }

    /**
     * Criterion that only accepts signatures which are not expired RIGHT NOW.
     *
     * @return criterion
     */
    public static SelectSignatureFromKey isSigNotExpired() {
        return isSigNotExpired(new Date());
    }

    /**
     * Criterion that only accepts signatures which are not expired at comparisonDate.
     *
     * @param comparisonDate comparison date
     * @return criterion
     */
    public static SelectSignatureFromKey isSigNotExpired(Date comparisonDate) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return !SignatureUtils.isSignatureExpired(signature, comparisonDate);
            }
        };
    }

    /**
     * Criterion that only accepts signatures which do not predate their signing key's creation date.
     *
     * @return criterion
     */
    public static SelectSignatureFromKey doesNotPredateKeyCreationDate() {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                PGPPublicKey creator = keyRing.getPublicKey(signature.getKeyID());
                if (creator == null) {
                    return false;
                }
                return doesNotPredateKeyCreationDate(creator).accept(signature, key, keyRing);
            }
        };
    }

    /**
     * Criterion that only accepts signatures which do not predate the creation date of the provided key.
     *
     * @param creator key
     * @return criterion
     */
    public static SelectSignatureFromKey doesNotPredateKeyCreationDate(PGPPublicKey creator) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return !signature.getCreationTime().before(creator.getCreationTime());
            }
        };
    }

    /**
     * Criterion that only accepts signatures of the provided signature version.
     *
     * @param version signature version
     * @return criterion
     */
    public static SelectSignatureFromKey isVersion(int version) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.getVersion() == version;
            }
        };
    }

    /**
     * Criterion that only accepts signatures that are of the provided {@link SignatureType}.
     *
     * @param signatureType signature type that shall be accepted
     * @return criterion
     */
    public static SelectSignatureFromKey isOfType(SignatureType signatureType) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.getSignatureType() == signatureType.getCode();
            }
        };
    }

    /**
     * Compose different {@link SelectSignatureFromKey} by combining them with a logic AND.
     * A signature will only be accepted, iff it satisfies every selector from selectors.
     *
     * @param selectors one or more selectors
     * @return combined selector using AND operator
     */
    public static SelectSignatureFromKey and(SelectSignatureFromKey... selectors) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                for (SelectSignatureFromKey selector : selectors) {
                    if (!selector.accept(signature, key, keyRing)) {
                        return false;
                    }
                }
                return true;
            }
        };
    }

    /**
     * Compose different {@link SelectSignatureFromKey} by combining them with a logic OR.
     * A signature will only be accepted, iff it satisfies at least one selector from selectors.
     *
     * @param selectors one or more selectors
     * @return combined selector using OR operator
     */
    public static SelectSignatureFromKey or(SelectSignatureFromKey... selectors) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                boolean accept = false;
                for (SelectSignatureFromKey selector : selectors) {
                    accept |= selector.accept(signature, key, keyRing);
                }
                return accept;
            }
        };
    }

    /**
     * Negate the result of a {@link SelectSignatureFromKey} implementations {@link #accept(PGPSignature, PGPPublicKey, PGPKeyRing)}.
     * The resulting {@link SelectSignatureFromKey} will only accept signatures that are rejected by the provided selector
     * and reject those that are accepted by it.
     *
     * @param selector selector whose logic operation will be negated
     * @return negated selector
     */
    public static SelectSignatureFromKey not(SelectSignatureFromKey selector) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return !selector.accept(signature, key, keyRing);
            }
        };
    }
}
