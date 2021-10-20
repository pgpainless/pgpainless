// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm.negotiation;

import java.util.Set;

import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.policy.Policy;

public interface HashAlgorithmNegotiator {

    HashAlgorithm negotiateHashAlgorithm(Set<HashAlgorithm> orderedHashAlgorithmPreferencesSet);

    static HashAlgorithmNegotiator negotiateSignatureHashAlgorithm(Policy policy) {
        return negotiateByPolicy(policy.getSignatureHashAlgorithmPolicy());
    }

    static HashAlgorithmNegotiator negotiateRevocationSignatureAlgorithm(Policy policy) {
        return negotiateByPolicy(policy.getRevocationSignatureHashAlgorithmPolicy());
    }

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
