// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

public class Trustworthiness {

    private final int amount;
    private final int depth;

    public static final int THRESHOLD_FULLY_CONVINCED = 120;
    public static final int THRESHOLD_MARGINALLY_CONVINCED = 60;
    public static final int THRESHOLD_NOT_TRUSTED = 0;

    public Trustworthiness(int amount, int depth) {
        this.amount = capAmount(amount);
        this.depth = capDepth(depth);
    }

    public int getAmount() {
        return amount;
    }

    public int getDepth() {
        return depth;
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
        return new Builder(THRESHOLD_MARGINALLY_CONVINCED);
    }

    /**
     * This means that we do not trust the key.
     * Can be used to overwrite previous trust.
     *
     * @return builder
     */
    public static Builder untrusted() {
        return new Builder(THRESHOLD_NOT_TRUSTED);
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
         * The key is a level <pre>n</pre> meta introducer.
         * This key can introduce meta introducers of depth <pre>n - 1</pre>.
         *
         * @param n depth
         * @return trust
         */
        public Trustworthiness levelNIntroducer(int n) {
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
