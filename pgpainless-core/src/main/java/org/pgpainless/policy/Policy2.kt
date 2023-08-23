package org.pgpainless.policy

import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.util.DateUtil
import java.util.*

class Policy2 {

    /**
     * Create a HashAlgorithmPolicy which accepts all [HashAlgorithms][HashAlgorithm] from the
     * given map, if the queried usage date is BEFORE the respective termination date.
     * A termination date value of <pre>null</pre> means no termination, resulting in the algorithm being
     * acceptable, regardless of usage date.
     *
     * @param defaultHashAlgorithm default hash algorithm
     * @param algorithmTerminationDates map of acceptable algorithms and their termination dates
     */
    class HashAlgorithmPolicy(
            val defaultHashAlgorithm: HashAlgorithm,
            val acceptableHashAlgorithmsAndTerminationDates: Map<HashAlgorithm, Date?>) {

        /**
         * Create a [HashAlgorithmPolicy] which accepts all  [HashAlgorithms][HashAlgorithm] listed in
         * the given list, regardless of usage date.
         *
         * @param defaultHashAlgorithm default hash algorithm (e.g. used as fallback if negotiation fails)
         * @param acceptableHashAlgorithms list of acceptable hash algorithms
         */
        constructor(defaultHashAlgorithm: HashAlgorithm, acceptableHashAlgorithms: List<HashAlgorithm>) :
                this(defaultHashAlgorithm, acceptableHashAlgorithms.associateWith { null })

        fun isAcceptable(hashAlgorithm: HashAlgorithm) = isAcceptable(hashAlgorithm, Date())

        /**
         * Return true, if the given algorithm is acceptable for the given usage date.
         *
         * @param hashAlgorithm algorithm
         * @param referenceTime usage date (e.g. signature creation time)
         *
         * @return acceptance
         */
        fun isAcceptable(hashAlgorithm: HashAlgorithm, referenceTime: Date): Boolean {
            if (!acceptableHashAlgorithmsAndTerminationDates.containsKey(hashAlgorithm))
                return false
            val terminationDate = acceptableHashAlgorithmsAndTerminationDates[hashAlgorithm]
            if (terminationDate == null) {
                return true
            }
            return terminationDate > referenceTime
        }

        fun isAcceptable(algorithmId: Int, referenceTime: Date): Boolean {
            HashAlgorithm.fromId(algorithmId).let {
                if (it == null) {
                    return false
                }
                return isAcceptable(it, referenceTime)
            }
        }

        fun isAcceptable(algorithmId: Int) = isAcceptable(algorithmId, Date())

        companion object {
            @JvmStatic
            val smartSignatureHashAlgorithmPolicy = HashAlgorithmPolicy(HashAlgorithm.SHA512, buildMap {
                put(HashAlgorithm.MD5, DateUtil.parseUTCDate("1997-02-01 00:00:00 UTC"))
                put(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2013-02-01 00:00:00 UTC"))
                put(HashAlgorithm.RIPEMD160, DateUtil.parseUTCDate("2013-02-01 00:00:00 UTC"))
                put(HashAlgorithm.SHA224, null)
                put(HashAlgorithm.SHA256, null)
                put(HashAlgorithm.SHA384, null)
                put(HashAlgorithm.SHA512, null)
                put(HashAlgorithm.SHA3_256, null)
                put(HashAlgorithm.SHA3_512, null)
            })

            /**
             * [HashAlgorithmPolicy] which only accepts signatures made using algorithms which are acceptable
             * according to 2022 standards.
             *
             * Particularly this policy only accepts algorithms from the SHA2 and SHA3 families.
             *
             * @return static signature algorithm policy
             */
            @JvmStatic
            val static2022SignatureHashAlgorithmPolicy =
                    HashAlgorithmPolicy(HashAlgorithm.SHA512, listOf(
                            HashAlgorithm.SHA224,
                            HashAlgorithm.SHA256,
                            HashAlgorithm.SHA384,
                            HashAlgorithm.SHA512,
                            HashAlgorithm.SHA3_256,
                            HashAlgorithm.SHA3_512))

            /**
             * Hash algorithm policy for revocation signatures, which accepts SHA1 and SHA2 algorithms, as well as RIPEMD160.
             *
             * @return static revocation signature hash algorithm policy
             */
            @JvmStatic
            val static2022RevocationSignatureHashAlgorithmPolicy =
                    HashAlgorithmPolicy(HashAlgorithm.SHA512, listOf(
                            HashAlgorithm.RIPEMD160,
                            HashAlgorithm.SHA1,
                            HashAlgorithm.SHA224,
                            HashAlgorithm.SHA256,
                            HashAlgorithm.SHA384,
                            HashAlgorithm.SHA512,
                            HashAlgorithm.SHA3_256,
                            HashAlgorithm.SHA3_512))
        }
    }

    class CompressionAlgorithmPolicy(
            val defaultCompressionAlgorithm: CompressionAlgorithm,
            val acceptableCompressionAlgorithms: List<CompressionAlgorithm>) {

        fun isAcceptable(algorithm: CompressionAlgorithm) = acceptableCompressionAlgorithms.contains(algorithm)
        fun isAcceptable(algorithmId: Int) =
    }

    companion object {
        private var INSTANCE: Policy2? = null
        fun getInstance(): Policy2 {
            if (INSTANCE == null) {
                INSTANCE = Policy2()
            }
            return INSTANCE!!
        }
    }
}