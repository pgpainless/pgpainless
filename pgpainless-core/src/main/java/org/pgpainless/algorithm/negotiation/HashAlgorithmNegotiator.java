// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm.negotiation;

import java.util.Set;

import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.policy.Policy;

/**
 * Interface for a class that negotiates {@link HashAlgorithm HashAlgorithms}.
 *
 * You can provide your own implementation using custom logic by implementing the
 * {@link #negotiateHashAlgorithm(Set)} method.
 */
public interface HashAlgorithmNegotiator {

    /**
     * Pick one {@link HashAlgorithm} from the ordered set of acceptable algorithms.
     *
     * @param orderedHashAlgorithmPreferencesSet hash algorithm preferences
     * @return picked algorithms
     */
    HashAlgorithm negotiateHashAlgorithm(Set<HashAlgorithm> orderedHashAlgorithmPreferencesSet);

    /**
     * Return an instance that negotiates {@link HashAlgorithm HashAlgorithms} used for non-revocation signatures
     * based on the given {@link Policy}.
     *
     * @param policy algorithm policy
     * @return negotiator
     */
    static HashAlgorithmNegotiator negotiateSignatureHashAlgorithm(Policy policy) {
        return negotiateByPolicy(policy.getSignatureHashAlgorithmPolicy());
    }

    /**
     * Return an instance that negotiates {@link HashAlgorithm HashAlgorithms} used for revocation signatures
     * based on the given {@link Policy}.
     *
     * @param policy algorithm policy
     * @return negotiator
     */
    static HashAlgorithmNegotiator negotiateRevocationSignatureAlgorithm(Policy policy) {
        return negotiateByPolicy(policy.getRevocationSignatureHashAlgorithmPolicy());
    }

    /**
     * Return an instance that negotiates {@link HashAlgorithm HashAlgorithms} based on the given
     * {@link Policy.HashAlgorithmPolicy}.
     *
     * @param hashAlgorithmPolicy algorithm policy for hash algorithms
     * @return negotiator
     */
    static HashAlgorithmNegotiator negotiateByPolicy(Policy.HashAlgorithmPolicy hashAlgorithmPolicy) {
        return new HashAlgorithmNegotiator() {
            @Override
            public HashAlgorithm negotiateHashAlgorithm(Set<HashAlgorithm> orderedPreferencesSet) {
                for (HashAlgorithm preference : orderedPreferencesSet) {
                    if (hashAlgorithmPolicy.isAcceptable(preference)) {
                        return preference;
                    }
                }
                return hashAlgorithmPolicy.defaultHashAlgorithm();
            }
        };
    }
}
