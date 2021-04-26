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

public abstract class SelectSignatureFromKey {

    private static final Logger LOGGER = Logger.getLogger(SelectSignatureFromKey.class.getName());

    public static SelectSignatureFromKey isValidAt(Date validationDate) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                Date expirationDate = SignatureUtils.getSignatureExpirationDate(signature);
                return !signature.getCreationTime().after(validationDate) && (expirationDate == null || expirationDate.after(validationDate));
            }
        };
    }

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

                boolean subkeyBindingSigValid;
                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), primaryKey);
                    subkeyBindingSigValid = signature.verifyCertification(primaryKey, subkey);
                } catch (PGPException e) {
                    LOGGER.log(Level.INFO, "Verification of subkey binding signature failed.", e);
                    return false;
                }

                if (!subkeyBindingSigValid) {
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

                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), subkey);
                    return signature.verifyCertification(primaryKey, subkey);
                } catch (PGPException e) {
                    return false;
                }
            }
        };
    }

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

                try {
                    signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signer);
                    return signature.verifyCertification(signee);
                } catch (PGPException e) {
                    return false;
                }
            }
        };
    }

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

    public static SelectSignatureFromKey isValidSubkeyRevocationSignature() {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return isValidSubkeyRevocationSignature(key, keyRing.getPublicKey())
                        .accept(signature, key, keyRing);
            }
        };
    }

    public static SelectSignatureFromKey isValidSubkeyRevocationSignature(PGPPublicKey subkey, PGPPublicKey primaryKey) {
        return SelectSignatureFromKey.and(
                isVersion4Signature(),
                isOfType(SignatureType.SUBKEY_REVOCATION),
                isCreatedBy(primaryKey),
                isVerifyingSignatureOnKeys(primaryKey, subkey, primaryKey)
        );
    }

    public static SelectSignatureFromKey isValidCertificationRevocationSignature(PGPPublicKey revoker, String userId) {
        return and(
                isVersion4Signature(),
                isCreatedBy(revoker),
                isOfType(SignatureType.CERTIFICATION_REVOCATION),
                isValidSignatureOnUserId(userId, revoker)
        );
    }

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

    public static SelectSignatureFromKey isCertification() {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.isCertification();
            }
        };
    }

    public static SelectSignatureFromKey isWellFormed() {
        return and(
                hasCreationTimeSubpacket(),
                doesNotPredateKeyCreationDate()
        );
    }

    public static SelectSignatureFromKey isVersion4Signature() {
        return isVersion(4);
    }

    public static SelectSignatureFromKey hasCreationTimeSubpacket() {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.getHashedSubPackets().getSignatureCreationTime() != null;
            }
        };
    }

    public static SelectSignatureFromKey isCreatedBy(PGPPublicKey publicKey) {
        return isCreatedBy(publicKey.getKeyID());
    }

    public static SelectSignatureFromKey isCreatedBy(long keyId) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.getKeyID() == keyId;
            }
        };
    }

    public static SelectSignatureFromKey isSigNotExpired() {
        return isSigNotExpired(new Date());
    }

    public static SelectSignatureFromKey isSigNotExpired(Date comparisonDate) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return !SignatureUtils.isSignatureExpired(signature, comparisonDate);
            }
        };
    }

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

    public static SelectSignatureFromKey doesNotPredateKeyCreationDate(PGPPublicKey creator) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return !signature.getCreationTime().before(creator.getCreationTime());
            }
        };
    }

    public static SelectSignatureFromKey isVersion(int version) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.getVersion() == version;
            }
        };
    }

    public static SelectSignatureFromKey isOfType(SignatureType signatureType) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return signature.getSignatureType() == signatureType.getCode();
            }
        };
    }

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

    public static SelectSignatureFromKey not(SelectSignatureFromKey selector) {
        return new SelectSignatureFromKey() {
            @Override
            public boolean accept(PGPSignature signature, PGPPublicKey key, PGPKeyRing keyRing) {
                return !selector.accept(signature, key, keyRing);
            }
        };
    }
}
