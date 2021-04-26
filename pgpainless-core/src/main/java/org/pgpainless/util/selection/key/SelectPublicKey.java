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
package org.pgpainless.util.selection.key;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.util.CollectionUtils;
import org.pgpainless.signature.SelectSignatureFromKey;

public abstract class SelectPublicKey {

    private static final Logger LOGGER = Logger.getLogger(SelectPublicKey.class.getName());

    public abstract boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing);

    public List<PGPPublicKey> selectPublicKeys(PGPKeyRing keyRing) {
        List<PGPPublicKey> selected = new ArrayList<>();
        List<PGPPublicKey> publicKeys = CollectionUtils.iteratorToList(keyRing.getPublicKeys());
        for (PGPPublicKey publicKey : publicKeys) {
            if (accept(publicKey, keyRing)) {
                selected.add(publicKey);
            }
        }
        return selected;
    }

    public PGPPublicKey firstMatch(PGPKeyRing keyRing) {
        List<PGPPublicKey> selected = selectPublicKeys(keyRing);
        if (selected.isEmpty()) {
            return null;
        }
        return selected.get(0);
    }

    public static SelectPublicKey isPrimaryKey() {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return publicKey.isMasterKey() && keyRing.getPublicKey().getKeyID() == publicKey.getKeyID();
            }
        };
    }

    public static SelectPublicKey isSubKey() {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                if (isPrimaryKey().accept(publicKey, keyRing)) {
                    return false;
                }
                PGPPublicKey primaryKey = keyRing.getPublicKey();
                SelectSignatureFromKey bindingSigSelector = SelectSignatureFromKey.isValidSubkeyBindingSignature(primaryKey, publicKey);

                Iterator<PGPSignature> bindingSigs = publicKey.getSignaturesOfType(SignatureType.SUBKEY_BINDING.getCode());
                while (bindingSigs.hasNext()) {
                    if (bindingSigSelector.accept(bindingSigs.next(), publicKey, keyRing)) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    public static SelectPublicKey validForUserId(String userId) {
        return validForUserId(userId, new Date());
    }

    public static SelectPublicKey validForUserId(String userId, Date validationDate) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                PGPPublicKey primaryKey = keyRing.getPublicKey();

                // Has userid
                List<String> userIds = CollectionUtils.iteratorToList(primaryKey.getUserIDs());
                if (!userIds.contains(userId)) {
                    LOGGER.log(Level.INFO, "Keyring " + Long.toHexString(primaryKey.getKeyID()) + " does not contain user-id '" + userId + "'");
                }

                // is primary key revoked
                if (isRevoked(validationDate).accept(primaryKey, keyRing)) {
                    LOGGER.log(Level.INFO, "Primary key " + Long.toHexString(primaryKey.getKeyID()) + " has been revoked.");
                    return false;
                }

                // is userid expired
                if (isExpired(userId, validationDate).accept(primaryKey, keyRing)) {
                    LOGGER.log(Level.INFO, "Primary key " + Long.toHexString(primaryKey.getKeyID()) + " has expired.");
                    return false;
                }

                // is userid revoked
                if (isUserIdRevoked(userId, validationDate).accept(primaryKey, keyRing)) {
                    LOGGER.log(Level.INFO, "Primary key " + Long.toHexString(primaryKey.getKeyID()) + " has been revoked.");
                }

                // UserId on primary key valid
                try {
                    boolean userIdValid = SignatureUtils.isUserIdValid(primaryKey, userId);
                    if (!userIdValid) {
                        LOGGER.log(Level.INFO, "User-id '" + userId + "' is not valid for key " + Long.toHexString(primaryKey.getKeyID()));
                        return false;
                    }
                } catch (PGPException e) {
                    LOGGER.log(Level.INFO, "Could not verify signature on primary key " + Long.toHexString(primaryKey.getKeyID()) + " and user-id '" + userId + "'", e);
                    return false;
                }

                // is primary key
                if (publicKey == primaryKey) {
                    return true;
                }

                // is subkey
                if (!isSubKey().accept(publicKey, keyRing)) {
                    LOGGER.log(Level.INFO, "Key " + Long.toHexString(publicKey.getKeyID()) + " is not valid subkey of key " + Long.toHexString(primaryKey.getKeyID()));
                    return false;
                }
                // is subkey revoked
                if (isRevoked(validationDate).accept(publicKey, keyRing)) {
                    LOGGER.log(Level.INFO, "Subkey " + Long.toHexString(publicKey.getKeyID()) + " of key " + Long.toHexString(primaryKey.getKeyID()) + " is revoked");
                    return false;
                }

                return true;
            }
        };
    }

    public static SelectPublicKey isRevoked(Date validationDate) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                if (publicKey.isMasterKey()) {
                    if (!publicKey.hasRevocation()) {
                        return false;
                    } else {
                        SelectSignatureFromKey validRevocation = SelectSignatureFromKey.isValidKeyRevocationSignature(publicKey);
                        Iterator<PGPSignature> revSigIt = publicKey.getSignaturesOfType(SignatureType.KEY_REVOCATION.getCode());
                        List<PGPSignature> revSigs = CollectionUtils.iteratorToList(revSigIt);
                        List<PGPSignature> validRevSigs = validRevocation.select(revSigs, publicKey, keyRing);
                        return !validRevSigs.isEmpty();
                    }
                } else {
                    return publicKey.hasRevocation() || keyRing.getPublicKey().hasRevocation();
                }
            }
        };
    }

    public static SelectPublicKey isExpired(String userId, Date validationDate) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return false;
            }
        };
    }

    public static SelectPublicKey isUserIdRevoked(String userId, Date validationDate) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return false;
            }
        };
    }

    private static SelectPublicKey hasKeyRevocationSignature() {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                Iterator<PGPSignature> it = publicKey.getSignatures();
                while (it.hasNext()) {
                    PGPSignature signature = it.next();
                    if (SelectSignatureFromKey.isValidKeyRevocationSignature(publicKey).accept(signature, publicKey, keyRing)) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    private static SelectPublicKey hasSubkeyRevocationSignature() {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                Iterator<PGPSignature> it = publicKey.getKeySignatures();
                while (it.hasNext()) {
                    PGPSignature signature = it.next();
                    if (SelectSignatureFromKey.isValidSubkeyRevocationSignature(publicKey, keyRing.getPublicKey()).accept(signature, publicKey, keyRing)) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    private static SelectPublicKey isSubkeyOfRevokedPrimaryKey() {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return isSubKey().accept(publicKey, keyRing)
                        && SelectPublicKey.hasKeyRevocationSignature().accept(keyRing.getPublicKey(), keyRing);
            }
        };
    }

    public static SelectPublicKey hasKeyFlag(String userId, KeyFlag keyFlag) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return false;
            }
        };
    }

    public static SelectPublicKey supportsAlgorithm(SymmetricKeyAlgorithm symmetricKeyAlgorithm) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return false;
            }
        };
    }

    public static SelectPublicKey supportsAlgorithm(HashAlgorithm hashAlgorithm) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return false;
            }
        };
    }

    public static SelectPublicKey supportsAlgorithm(CompressionAlgorithm compressionAlgorithm) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return false;
            }
        };
    }

    public static SelectPublicKey and(SelectPublicKey... selectors) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                for (SelectPublicKey selector : selectors) {
                    if (!selector.accept(publicKey, keyRing)) {
                        return false;
                    }
                }
                return true;
            }
        };
    }

    public static SelectPublicKey or(SelectPublicKey... selectors) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                boolean accept = false;
                for (SelectPublicKey selector : selectors) {
                    accept |= selector.accept(publicKey, keyRing);
                }
                return accept;
            }
        };
    }

    public static SelectPublicKey not(SelectPublicKey selector) {
        return new SelectPublicKey() {
            @Override
            public boolean accept(PGPPublicKey publicKey, PGPKeyRing keyRing) {
                return !selector.accept(publicKey, keyRing);
            }
        };
    }
}
