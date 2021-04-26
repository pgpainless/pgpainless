/*
 * Copyright 2020 Paul Schaub.
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
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.key.util.OpenPgpKeyAttributeUtil;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

public class SignatureUtils {

    public static PGPSignatureGenerator getSignatureGeneratorFor(PGPSecretKey singingKey) {
        return getSignatureGeneratorFor(singingKey.getPublicKey());
    }

    public static PGPSignatureGenerator getSignatureGeneratorFor(PGPPublicKey signingPubKey) {
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                getPgpContentSignerBuilderForKey(signingPubKey));
        return signatureGenerator;
    }

    private static BcPGPContentSignerBuilder getPgpContentSignerBuilderForKey(PGPPublicKey publicKey) {
        List<HashAlgorithm> preferredHashAlgorithms = OpenPgpKeyAttributeUtil.getPreferredHashAlgorithms(publicKey);
        if (preferredHashAlgorithms.isEmpty()) {
            preferredHashAlgorithms = OpenPgpKeyAttributeUtil.guessPreferredHashAlgorithms(publicKey);
        }
        HashAlgorithm hashAlgorithm = negotiateHashAlgorithm(preferredHashAlgorithms);

        return new BcPGPContentSignerBuilder(publicKey.getAlgorithm(), hashAlgorithm.getAlgorithmId());
    }

    private static HashAlgorithm negotiateHashAlgorithm(List<HashAlgorithm> preferredHashAlgorithms) {
        if (preferredHashAlgorithms.isEmpty()) {
            return PGPainless.getPolicy().getSignatureHashAlgorithmPolicy().defaultHashAlgorithm();
        }
        return preferredHashAlgorithms.get(0);
    }

    public static PGPSignature getLatestValidSignature(PGPPublicKey publicKey, List<PGPSignature> signatures, PGPKeyRing keyRing) throws PGPException {
        List<PGPSignature> valid = new ArrayList<>();
        for (PGPSignature signature : signatures) {
            long issuerID = signature.getKeyID();
            PGPPublicKey issuer = KeyRingUtils.getPublicKeyFrom(keyRing, issuerID);
            if (issuer == null) {
                continue;
            }

            if (!isSignatureValid(signature, issuer, publicKey)) {
                continue;
            }

            if (isSignatureExpired(signature)) {
                continue;
            }
            valid.add(signature);
        }
        sortByCreationTimeAscending(valid);

        return valid.isEmpty() ? null : valid.get(valid.size() - 1);
    }

    public static boolean isSignatureValid(PGPSignature signature, PGPPublicKey issuer, PGPPublicKey target) throws PGPException {
        SignatureType signatureType = SignatureType.valueOf(signature.getSignatureType());
        switch (signatureType) {
            case BINARY_DOCUMENT:
            case CANONICAL_TEXT_DOCUMENT:
            case STANDALONE:
            case TIMESTAMP:
            case THIRD_PARTY_CONFIRMATION:
                throw new IllegalArgumentException("Signature is not a key signature.");
            case GENERIC_CERTIFICATION:
            case NO_CERTIFICATION:
            case CASUAL_CERTIFICATION:
            case POSITIVE_CERTIFICATION:
            case DIRECT_KEY:
                return isSelfSignatureValid(signature, issuer);
            case KEY_REVOCATION:
            case CERTIFICATION_REVOCATION:
                return isRevocationSignatureValid(signature, issuer);
            case SUBKEY_BINDING:
            case PRIMARYKEY_BINDING:
            case SUBKEY_REVOCATION:
                return isKeyOnKeySignatureValid(signature, issuer, target);
        }
        return false;
    }

    public static boolean isKeyOnKeySignatureValid(PGPSignature signature, PGPPublicKey issuer, PGPPublicKey target) throws PGPException {
        signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), issuer);
        return signature.verifyCertification(issuer, target);
    }

    public static boolean isSelfSignatureValid(PGPSignature signature, PGPPublicKey publicKey) throws PGPException {
        if (!PGPainless.getPolicy().getSignatureHashAlgorithmPolicy().isAcceptable(signature.getHashAlgorithm())) {
            return false;
        }
        for (Iterator<String> it = publicKey.getUserIDs(); it.hasNext(); ) {
            String userId = it.next();
            boolean valid = isSelfSignatureOnUserIdValid(signature, userId, publicKey);
            if (valid) {
                return true;
            }
        }
        return false;
    }

    public static boolean isRevocationSignatureValid(PGPSignature signature, PGPPublicKey publicKey) throws PGPException {
        if (!PGPainless.getPolicy().getRevocationSignatureHashAlgorithmPolicy().isAcceptable(signature.getHashAlgorithm())) {
            return false;
        }
        for (Iterator<String> it = publicKey.getUserIDs(); it.hasNext(); ) {
            String userId = it.next();
            boolean valid = isSelfSignatureOnUserIdValid(signature, userId, publicKey);
            if (valid) {
                return true;
            }
        }
        return false;
    }

    public static boolean isSelfSignatureOnUserIdValid(PGPSignature signature, String userId, PGPPublicKey publicKey) throws PGPException {
        signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), publicKey);
        return signature.verifyCertification(userId, publicKey);
    }

    public static Date getKeyExpirationDate(Date keyCreationDate, PGPSignature signature) {
        KeyExpirationTime keyExpirationTime = SignatureSubpacketsUtil.getKeyExpirationTime(signature);
        long expiresInSecs = keyExpirationTime == null ? 0 : keyExpirationTime.getTime();
        return datePlusSeconds(keyCreationDate, expiresInSecs);
    }

    public static Date getSignatureExpirationDate(PGPSignature signature) {
        Date creationDate = signature.getCreationTime();
        SignatureExpirationTime signatureExpirationTime = SignatureSubpacketsUtil.getSignatureExpirationTime(signature);
        long expiresInSecs = signatureExpirationTime == null ? 0 : signatureExpirationTime.getTime();
        return datePlusSeconds(creationDate, expiresInSecs);
    }

    public static Date datePlusSeconds(Date date, long seconds) {
        if (seconds == 0) {
            return null;
        }
        return new Date(date.getTime() + 1000 * seconds);
    }

    public static boolean isSignatureExpired(PGPSignature signature) {
        return isSignatureExpired(signature, new Date());
    }

    public static boolean isSignatureExpired(PGPSignature signature, Date comparisonDate) {
        Date expirationDate = getSignatureExpirationDate(signature);
        if (expirationDate == null) {
            return false;
        }
        return comparisonDate.after(expirationDate);
    }

    public static void sortByCreationTimeAscending(List<PGPSignature> signatures) {
        Collections.sort(signatures, new Comparator<PGPSignature>() {
            @Override
            public int compare(PGPSignature s1, PGPSignature s2) {
                return s1.getCreationTime().compareTo(s2.getCreationTime());
            }
        });
    }

    public static List<PGPSignature> getBindingSignatures(PGPPublicKey subKey, long primaryKeyId) {
        List<PGPSignature> signatures = new ArrayList<>();
        List<PGPSignature> bindingSigs = getSignaturesOfTypes(subKey, SignatureType.SUBKEY_BINDING);
        for (PGPSignature signature : bindingSigs) {
            if (signature.getKeyID() != primaryKeyId) {
                continue;
            }
            signatures.add(signature);
        }
        return signatures;
    }

    public static List<PGPSignature> getSignaturesOfTypes(PGPPublicKey publicKey, SignatureType... types) {
        List<PGPSignature> signatures = new ArrayList<>();
        for (SignatureType type : types) {
            Iterator<?> it = publicKey.getSignaturesOfType(type.getCode());
            while (it.hasNext()) {
                Object o = it.next();
                if (o instanceof PGPSignature) {
                    signatures.add((PGPSignature) o);
                }
            }
        }
        sortByCreationTimeAscending(signatures);
        return signatures;
    }

    public static List<PGPSignature> getSignaturesForUserId(PGPPublicKey publicKey, String userId) {
        List<PGPSignature> signatures = new ArrayList<>();
        Iterator<?> it = publicKey.getSignaturesForID(userId);
        while (it != null && it.hasNext()) {
            Object o = it.next();
            if (o instanceof PGPSignature) {
                signatures.add((PGPSignature) o);
            }
        }
        sortByCreationTimeAscending(signatures);
        return signatures;
    }

    public static PGPSignature getLatestSelfSignatureForUserId(PGPPublicKey publicKey, String userId) throws PGPException {
        List<PGPSignature> valid = new ArrayList<>();
        List<PGPSignature> signatures = getSignaturesForUserId(publicKey, userId);
        for (PGPSignature signature : signatures) {
            if (isSelfSignatureOnUserIdValid(signature, userId, publicKey)) {
                valid.add(signature);
            }
        }
        return valid.isEmpty() ? null : valid.get(valid.size() - 1);
    }

    public static boolean isUserIdValid(PGPPublicKey publicKey, String userId) throws PGPException {
        return isUserIdValid(publicKey, userId, new Date());
    }

    public static boolean isUserIdValid(PGPPublicKey publicKey, String userId, Date validationDate) throws PGPException {
        PGPSignature latestSelfSig = getLatestSelfSignatureForUserId(publicKey, userId);
        if (latestSelfSig == null) {
            return false;
        }
        if (latestSelfSig.getCreationTime().after(validationDate)) {
            // Signature creation date lays in the future.
            return false;
        }
        if (isSignatureExpired(latestSelfSig, validationDate)) {
            return false;
        }

        return latestSelfSig.getSignatureType() != SignatureType.CERTIFICATION_REVOCATION.getCode();
    }

    public static boolean isHardRevocation(PGPSignature signature) {

        SignatureType type = SignatureType.valueOf(signature.getSignatureType());
        if (type != SignatureType.KEY_REVOCATION && type != SignatureType.SUBKEY_REVOCATION && type != SignatureType.CERTIFICATION_REVOCATION) {
            // Not a revocation
            return false;
        }

        RevocationReason reasonSubpacket = SignatureSubpacketsUtil.getRevocationReason(signature);
        if (reasonSubpacket == null) {
            // no reason -> hard revocation
            return true;
        }
        return RevocationAttributes.Reason.isHardRevocation(reasonSubpacket.getRevocationReason());
    }
}
