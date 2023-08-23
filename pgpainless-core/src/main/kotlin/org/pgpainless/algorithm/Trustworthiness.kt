// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

/**
 * Facade class for [org.bouncycastle.bcpg.sig.TrustSignature].
 * A trust signature subpacket marks the trustworthiness of a certificate and defines its capabilities to act
 * as a trusted introducer.
 */
class Trustworthiness(amount: Int, depth: Int) {
    val depth = capDepth(depth)
    val amount = capAmount(amount)

    /**
     * Returns true, if the trust amount is equal to 0.
     * This means the key is not trusted.
     *
     * Otherwise return false
     * @return true if untrusted
     */
    fun isNotTrusted() = amount == NOT_TRUSTED

    /**
     * Return true if the certificate is at least marginally trusted.
     * That is the case, if the trust amount is greater than 0.
     *
     * @return true if the cert is at least marginally trusted
     */
    fun isMarginallyTrusted() = amount > NOT_TRUSTED

    /**
     * Return true if the certificate is fully trusted. That is the case if the trust amount is
     * greater than or equal to 120.
     *
     * @return true if the cert is fully trusted
     */
    fun isFullyTrusted() = amount >= THRESHOLD_FULLY_CONVINCED

    /**
     * Return true, if the cert is an introducer. That is the case if the depth is greater 0.
     *
     * @return true if introducer
     */
    fun isIntroducer() = depth >= 1

    /**
     * Return true, if the certified cert can introduce certificates with trust depth of <pre>otherDepth</pre>.
     *
     * @param otherDepth other certifications trust depth
     * @return true if the cert can introduce the other
     */
    fun canIntroduce(otherDepth: Int) = depth > otherDepth

    /**
     * Return true, if the certified cert can introduce certificates with the given <pre>other</pre> trust depth.
     *
     * @param other other certificates trust depth
     * @return true if the cert can introduce the other
     */
    fun canIntroduce(other: Trustworthiness) = canIntroduce(other.depth)

    companion object {
        const val THRESHOLD_FULLY_CONVINCED = 120 // greater or equal is fully trusted
        const val MARGINALLY_CONVINCED = 60 // default value for marginally convinced
        const val NOT_TRUSTED = 0 // 0 is not trusted

        @JvmStatic
        private val validRange = 0..255

        /**
         * This means that we are fully convinced of the trustworthiness of the key.
         *
         * @return builder
         */
        @JvmStatic
        fun fullyTrusted() = Builder(THRESHOLD_FULLY_CONVINCED)

        /**
         * This means that we are marginally (partially) convinced of the trustworthiness of the key.
         *
         * @return builder
         */
        @JvmStatic
        fun marginallyTrusted() = Builder(MARGINALLY_CONVINCED)

        /**
         * This means that we do not trust the key.
         * Can be used to overwrite previous trust.
         *
         * @return builder
         */
        @JvmStatic
        fun untrusted() = Builder(NOT_TRUSTED)

        @JvmStatic
        private fun capAmount(amount: Int): Int {
            if (amount !in validRange) {
                throw IllegalArgumentException("Trust amount MUST be a value between 0 and 255")
            }
            return amount
        }

        @JvmStatic
        private fun capDepth(depth: Int): Int {
            if (depth !in validRange) {
                throw IllegalArgumentException("Trust depth MUST be a value between 0 and 255")
            }
            return depth
        }
    }

    class Builder(val amount: Int) {

        /**
         * The key is a trusted introducer (depth 1).
         * Certifications made by this key are considered trustworthy.
         *
         * @return trust
         */
        fun introducer() = Trustworthiness(amount, 1)

        /**
         * The key is a meta introducer (depth 2).
         * This key can introduce trusted introducers of depth 1.
         *
         * @return trust
         */
        fun metaIntroducer() = Trustworthiness(amount, 2)

        /**
         * The key is a meta introducer of depth <pre>n</pre>.
         * This key can introduce meta introducers of depth <pre>n - 1</pre>.
         *
         * @param n depth
         * @return trust
         */
        fun metaIntroducerOfDepth(d: Int) = Trustworthiness(amount, d)
    }

}