// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

/**
 * Facade class for {@link org.bouncycastle.bcpg.sig.TrustSignature}.
 * A trust signature subpacket marks the trustworthiness of a certificate and defines its capabilities to act
 * as a trusted introducer.
 */
public class Trustworthiness {

    private final int amount;
    private final int depth;

    public static final int THRESHOLD_FULLY_CONVINCED = 120;
    public static final int MARGINALLY_CONVINCED = 60;
    public static final int NOT_TRUSTED = 0;

    public Trustworthiness(int amount, int depth) {
        this.amount = capAmount(amount);
        this.depth = capDepth(depth);
    }

    /**
     * Get the trust amount.
     * This value means how confident the issuer of the signature is in validity of the binding.
     *
     * @return trust amount
     */
    public int getAmount() {
        return amount;
    }

    /**
     * Get the depth of the trust signature.
     * This value controls, whether the certificate can act as a trusted introducer.
     *
     * @return depth
     */
    public int getDepth() {
        return depth;
    }

    /**
     * Returns true, if the trust amount is equal to 0.
     * This means the key is not trusted.
     *
     * Otherwise return false
     * @return true if untrusted
     */
    public boolean isNotTrusted() {
        return getAmount() == NOT_TRUSTED;
    }

    /**
     * Return true if the certificate is at least marginally trusted.
     * That is the case, if the trust amount is greater than 0.
     *
     * @return true if the cert is at least marginally trusted
     */
    public boolean isMarginallyTrusted() {
        return getAmount() > NOT_TRUSTED;
    }

    /**
     * Return true if the certificate is fully trusted. That is the case if the trust amount is
     * greater than or equal to 120.
     *
     * @return true if the cert is fully trusted
     */
    public boolean isFullyTrusted() {
        return getAmount() >= THRESHOLD_FULLY_CONVINCED;
    }

    /**
     * Return true, if the cert is an introducer. That is the case if the depth is greater 0.
     *
     * @return true if introducer
     */
    public boolean isIntroducer() {
        return getDepth() >= 1;
    }

    /**
     * Return true, if the certified cert can introduce certificates with trust depth of <pre>otherDepth</pre>.
     *
     * @param otherDepth other certifications trust depth
     * @return true if the cert can introduce the other
     */
    public boolean canIntroduce(int otherDepth) {
        return getDepth() > otherDepth;
    }

    /**
     * Return true, if the certified cert can introduce certificates with the given <pre>other</pre> trust depth.
     *
     * @param other other certificates trust depth
     * @return true if the cert can introduce the other
     */
    public boolean canIntroduce(Trustworthiness other) {
        return canIntroduce(other.getDepth());
    }

    /**
     * This means that we are fully convinced of the trustworthiness of the key.
     *
     * @return builder
     */
    public static Builder fullyTrusted() {
        return new Builder(THRESHOLD_FULLY_CONVINCED);
    }

    /**
     * This means that we are marginally (partially) convinced of the trustworthiness of the key.
     *
     * @return builder
     */
    public static Builder marginallyTrusted() {
        return new Builder(MARGINALLY_CONVINCED);
    }

    /**
     * This means that we do not trust the key.
     * Can be used to overwrite previous trust.
     *
     * @return builder
     */
    public static Builder untrusted() {
        return new Builder(NOT_TRUSTED);
    }

    public static final class Builder {

        private final int amount;

        private Builder(int amount) {
            this.amount = amount;
        }

        /**
         * The key is a trusted introducer (depth 1).
         * Certifications made by this key are considered trustworthy.
         *
         * @return trust
         */
        public Trustworthiness introducer() {
            return new Trustworthiness(amount, 1);
        }

        /**
         * The key is a meta introducer (depth 2).
         * This key can introduce trusted introducers of depth 1.
         *
         * @return trust
         */
        public Trustworthiness metaIntroducer() {
            return new Trustworthiness(amount, 2);
        }

        /**
         * The key is a meta introducer of depth <pre>n</pre>.
         * This key can introduce meta introducers of depth <pre>n - 1</pre>.
         *
         * @param n depth
         * @return trust
         */
        public Trustworthiness metaIntroducerOfDepth(int n) {
            return new Trustworthiness(amount, n);
        }
    }

    private static int capAmount(int amount) {
        if (amount < 0 || amount > 255) {
            throw new IllegalArgumentException("Trust amount MUST be a value between 0 and 255");
        }
        return amount;
    }

    private static int capDepth(int depth) {
        if (depth < 0 || depth > 255) {
            throw new IllegalArgumentException("Trust depth MUST be a value between 0 and 255");
        }
        return depth;
    }

}
