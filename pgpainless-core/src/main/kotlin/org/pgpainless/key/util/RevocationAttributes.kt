// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util

class RevocationAttributes(val reason: Reason, val description: String) {

    /**
     * Reason for revocation. There are two kinds of reasons: hard and soft reason.
     *
     * Soft revocation reasons gracefully disable keys or user-ids. Softly revoked keys can no
     * longer be used to encrypt data to or to generate signatures. Any signature made after a key
     * has been soft revoked is deemed invalid. Any signature made before the key has been soft
     * revoked stays valid. Soft revoked info can be re-certified at a later point.
     *
     * Hard revocation reasons on the other hand renders the key or user-id invalid immediately.
     * Hard reasons are suitable to use if for example a key got compromised. Any signature made
     * before or after a key has been hard revoked is no longer considered valid. Hard revoked
     * information can also not be re-certified.
     */
    enum class Reason(val code: Byte) {
        /**
         * The key or certification is being revoked without a reason. This is a HARD revocation
         * reason and cannot be undone.
         */
        NO_REASON(0),
        /**
         * The key was superseded by another key. This is a SOFT revocation reason and can be
         * undone.
         */
        KEY_SUPERSEDED(1),
        /**
         * The key has potentially been compromised. This is a HARD revocation reason and cannot be
         * undone.
         */
        KEY_COMPROMISED(2),
        /**
         * The key was retired and shall no longer be used. This is a SOFT revocation reason can can
         * be undone.
         */
        KEY_RETIRED(3),
        /** The user-id is no longer valid. This is a SOFT revocation reason and can be undone. */
        USER_ID_NO_LONGER_VALID(32),
        ;

        fun code() = code

        override fun toString(): String {
            return "$code - $name"
        }

        companion object {

            @JvmStatic private val MAP = values().associateBy { it.code }

            /**
             * Decode a machine-readable reason code.
             *
             * @param code byte
             * @return reason
             */
            @JvmStatic
            fun fromCode(code: Byte) =
                MAP[code] ?: throw IllegalArgumentException("Invalid revocation reason: $code")

            /**
             * Return true if the [Reason] the provided code encodes is a hard revocation reason,
             * false otherwise. Hard revocations cannot be undone, while keys or certifications with
             * soft revocations can be re-certified by placing another signature on them.
             *
             * @param code reason code
             * @return is hard
             */
            @JvmStatic
            fun isHardRevocation(code: Byte) = MAP[code]?.let { isHardRevocation(it) } ?: true

            /**
             * Return true if the given [Reason] is a hard revocation, false otherwise. Hard
             * revocations cannot be undone, while keys or certifications with soft revocations can
             * be re-certified by placing another signature on them.
             *
             * @param reason reason
             * @return is hard
             */
            @JvmStatic
            fun isHardRevocation(reason: Reason) =
                when (reason) {
                    KEY_SUPERSEDED,
                    KEY_RETIRED,
                    USER_ID_NO_LONGER_VALID -> false
                    else -> true
                }

            /**
             * Return true if the given reason code denotes a key revocation.
             *
             * @param code reason code
             * @return is key revocation
             */
            @JvmStatic
            fun isKeyRevocation(code: Byte) = MAP[code]?.let { isKeyRevocation(it) } ?: false

            /**
             * Return true if the given [Reason] denotes a key revocation.
             *
             * @param reason reason
             * @return is key revocation
             */
            @JvmStatic
            fun isKeyRevocation(reason: Reason) =
                when (reason) {
                    USER_ID_NO_LONGER_VALID -> false
                    else -> true
                }
        }
    }

    enum class RevocationType {
        KEY_REVOCATION,
        CERT_REVOCATION
    }

    companion object {
        @JvmStatic fun createKeyRevocation() = WithReason(RevocationType.KEY_REVOCATION)

        @JvmStatic fun createCertificateRevocation() = WithReason(RevocationType.CERT_REVOCATION)
    }

    class WithReason(val type: RevocationType) {

        fun withReason(reason: Reason): WithDescription {
            require(reasonTypeMatches(reason, type)) {
                "Reason $reason can only be used for ${if (type == RevocationType.KEY_REVOCATION) "certificate" else "key"} revocations."
            }
            return WithDescription(reason)
        }

        private fun reasonTypeMatches(reason: Reason, type: RevocationType): Boolean {
            return when (type) {
                RevocationType.KEY_REVOCATION -> reason != Reason.USER_ID_NO_LONGER_VALID
                RevocationType.CERT_REVOCATION ->
                    reason == Reason.USER_ID_NO_LONGER_VALID || reason == Reason.NO_REASON
            }
        }
    }

    class WithDescription(val reason: Reason) {
        fun withDescription(description: String): RevocationAttributes =
            RevocationAttributes(reason, description)

        fun withoutDescription() = RevocationAttributes(reason, "")
    }
}
