// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.authentication;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPPublicKeyRing;

public class CertificateAuthenticity {

    private final String userId;
    private final PGPPublicKeyRing certificate;
    private final Map<CertificationChain, Integer> certificationChains = new HashMap<>();
    private final int targetAmount;

    public CertificateAuthenticity(@Nonnull PGPPublicKeyRing certificate,
                                   @Nonnull String userId,
                                   @Nonnull Map<CertificationChain, Integer> certificationChains,
                                   int targetAmount) {
        this.userId = userId;
        this.certificate = certificate;
        this.certificationChains.putAll(certificationChains);
        this.targetAmount = targetAmount;
    }

    @Nonnull
    public String getUserId() {
        return userId;
    }

    @Nonnull
    public PGPPublicKeyRing getCertificate() {
        return certificate;
    }

    public int getTotalTrustAmount() {
        int total = 0;
        for (int v : certificationChains.values()) {
            total += v;
        }
        return total;
    }

    /**
     * Return the degree of authentication of the binding in percent.
     * 100% means full authentication.
     * Values smaller than 100% mean partial authentication.
     *
     * @return authenticity in percent
     */
    public int getAuthenticityPercentage() {
        return targetAmount * 100 / getTotalTrustAmount();
    }

    /**
     * Return true, if the binding is authenticated to a sufficient degree.
     *
     * @return true if total gathered evidence outweighs the target trust amount.
     */
    public boolean isAuthenticated() {
        return targetAmount <= getTotalTrustAmount();
    }

    /**
     * Return a map of {@link CertificationChain CertificationChains} and their respective effective trust amount.
     * The effective trust amount of a path might be smaller than its actual trust amount, for example if nodes of a
     * path are used multiple times.
     *
     * @return map of certification chains and their effective trust amounts
     */
    @Nonnull
    public Map<CertificationChain, Integer> getCertificationChains() {
        return Collections.unmodifiableMap(certificationChains);
    }

    public static class CertificationChain {
        private final int trustAmount;
        private final List<ChainLink> chainLinks = new ArrayList<>();

        /**
         * A chain of certifications.
         *
         * @param trustAmount actual trust amount of the chain
         * @param chainLinks links of the chain, starting at the trust-root, ending at the target.
         */
        public CertificationChain(int trustAmount, @Nonnull List<ChainLink> chainLinks) {
            this.trustAmount = trustAmount;
            this.chainLinks.addAll(chainLinks);
        }

        /**
         * Actual trust amount of the certification chain.
         * @return trust amount
         */
        public int getTrustAmount() {
            return trustAmount;
        }

        /**
         * Return all links in the chain, starting at the trust-root and ending at the target.
         * @return chain links
         */
        @Nonnull
        public List<ChainLink> getChainLinks() {
            return Collections.unmodifiableList(chainLinks);
        }
    }

    /**
     * A chain link contains a node in the trust chain.
     */
    public static class ChainLink {
        private final PGPPublicKeyRing certificate;

        /**
         * Create a chain link.
         * @param certificate node in the trust chain
         */
        public ChainLink(@Nonnull PGPPublicKeyRing certificate) {
            this.certificate = certificate;
        }

        /**
         * Return the certificate that belongs to the node.
         * @return certificate
         */
        @Nonnull
        public PGPPublicKeyRing getCertificate() {
            return certificate;
        }
    }
}
