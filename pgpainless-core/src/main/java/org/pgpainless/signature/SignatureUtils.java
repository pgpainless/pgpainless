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

import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
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
     * Return a content signer builder for the passed public key.
     *
     * The content signer will use a hash algorithm derived from the keys algorithm preferences.
     * If no preferences can be derived, the key will fall back to the default hash algorithm as set in
     * the {@link org.pgpainless.policy.Policy}.
     *
     * TODO: Move negotiation to negotiator class
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
