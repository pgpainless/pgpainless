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
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.key.util.OpenPgpKeyAttributeUtil;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

/**
 * Utility methods related to signatures.
 */
public class SignatureUtils {

    /**
     * Return a signature generator for the provided signing key.
     * The signature generator will follow the hash algorithm preferences of the signing key and pick the best algorithm.
     *
     * @param singingKey signing key
     * @return signature generator
     */
    public static PGPSignatureGenerator getSignatureGeneratorFor(PGPSecretKey singingKey) {
        return getSignatureGeneratorFor(singingKey.getPublicKey());
    }

    /**
     * Return a signature generator for the provided signing key.
     * The signature generator will follow the hash algorithm preferences of the signing key and pick the best algorithm.
     *
     * @param signingPubKey signing key
     * @return signature generator
     */
    public static PGPSignatureGenerator getSignatureGeneratorFor(PGPPublicKey signingPubKey) {
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                getPgpContentSignerBuilderForKey(signingPubKey));
        return signatureGenerator;
    }

    /**
     * Return a content signer builder fot the passed public key.
     *
     * The content signer will use a hash algorithm derived from the keys algorithm preferences.
     * If no preferences can be derived, the key will fall back to the default hash algorithm as set in
     * the {@link org.pgpainless.policy.Policy}.
     *
     * @param publicKey public key
     * @return content signer builder
     */
    private static PGPContentSignerBuilder getPgpContentSignerBuilderForKey(PGPPublicKey publicKey) {
        List<HashAlgorithm> preferredHashAlgorithms = OpenPgpKeyAttributeUtil.getPreferredHashAlgorithms(publicKey);
        if (preferredHashAlgorithms.isEmpty()) {
            preferredHashAlgorithms = OpenPgpKeyAttributeUtil.guessPreferredHashAlgorithms(publicKey);
        }
        HashAlgorithm hashAlgorithm = negotiateHashAlgorithm(preferredHashAlgorithms);

        return ImplementationFactory.getInstance().getPGPContentSignerBuilder(publicKey.getAlgorithm(), hashAlgorithm.getAlgorithmId());
    }

    /**
     * Negotiate an acceptable hash algorithm from the provided list of options.
     * Acceptance of hash algorithms can be changed by setting a custom {@link Policy}.
     *
     * @param preferredHashAlgorithms list of preferred hash algorithms of a key
     * @return first acceptable algorithm, or policies default hash algorithm
     */
    private static HashAlgorithm negotiateHashAlgorithm(List<HashAlgorithm> preferredHashAlgorithms) {
        Policy policy = PGPainless.getPolicy();
        for (HashAlgorithm option : preferredHashAlgorithms) {
            if (policy.getSignatureHashAlgorithmPolicy().isAcceptable(option)) {
                return option;
            }
        }

        return PGPainless.getPolicy().getSignatureHashAlgorithmPolicy().defaultHashAlgorithm();
    }

    /**
     * Return the latest valid signature on the provided public key.
     *
     * @param publicKey signed key
     * @param signatures signatures
     * @param keyRing key ring containing signature creator key
     * @return latest valid signature
     * @throws PGPException in case of a validation error
     */
    public static PGPSignature getLatestValidSignature(PGPPublicKey publicKey,
                                                       List<PGPSignature> signatures,
                                                       PGPKeyRing keyRing)
            throws PGPException {
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

    /**
     * Return true, iff a signature is valid.
     *
     * TODO: There is code duplication here ({@link SelectSignatureFromKey}, {@link SignatureChainValidator}, {@link SignatureValidator}).
     * @param signature signature to validate
     * @param issuer signing key
     * @param target signed key
     * @return true if signature is valid
     * @throws PGPException if a validation error occurs.
     */
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

    /**
     * Return a new date which represents the given date plus the given amount of seconds added.
     *
     * Since '0' is a special value in the OpenPGP specification when it comes to dates
     * (e.g. '0' means no expiration for expiration dates), this method will return 'null' if seconds is 0.
     *
     * @param date date
     * @param seconds number of seconds to be added
     * @return date plus seconds or null if seconds is '0'
     */
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
        return expirationDate != null && comparisonDate.after(expirationDate);
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

    /**
     * Return true if the provided signature is a hard revocation.
     * Hard revocations are revocation signatures which either carry a revocation reason of
     * {@link RevocationAttributes.Reason#KEY_COMPROMISED} or {@link RevocationAttributes.Reason#NO_REASON},
     * or no reason at all.
     *
     * @param signature signature
     * @return true if signature is a hard revocation
     */
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
