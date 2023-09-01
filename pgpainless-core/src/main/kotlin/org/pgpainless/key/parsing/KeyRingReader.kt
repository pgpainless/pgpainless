// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.parsing

import org.bouncycastle.openpgp.*
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.collection.PGPKeyRingCollection
import org.pgpainless.util.ArmorUtils
import java.io.IOException
import java.io.InputStream
import java.nio.charset.Charset
import kotlin.jvm.Throws

class KeyRingReader {

    /**
     * Read a [PGPKeyRing] (either [PGPSecretKeyRing] or [PGPPublicKeyRing]) from the given [InputStream].
     *
     * @param inputStream inputStream containing the OpenPGP key or certificate
     * @return key ring
     * @throws IOException in case of an IO error
     */
    @Throws(IOException::class)
    fun keyRing(inputStream: InputStream): PGPKeyRing? =
            readKeyRing(inputStream)

    /**
     * Read a [PGPKeyRing] (either [PGPSecretKeyRing] or [PGPPublicKeyRing]) from the given byte array.
     *
     * @param bytes byte array containing the OpenPGP key or certificate
     * @return key ring
     * @throws IOException in case of an IO error
     */
    @Throws(IOException::class)
    fun keyRing(bytes: ByteArray): PGPKeyRing? =
            keyRing(bytes.inputStream())

    /**
     * Read a [PGPKeyRing] (either [PGPSecretKeyRing] or [PGPPublicKeyRing]) from the given
     * ASCII armored string.
     *
     * @param asciiArmored ASCII armored OpenPGP key or certificate
     * @return key ring
     * @throws IOException in case of an IO error
     */
    @Throws(IOException::class)
    fun keyRing(asciiArmored: String): PGPKeyRing? =
            keyRing(asciiArmored.toByteArray(UTF8))

    @Throws(IOException::class)
    fun publicKeyRing(inputStream: InputStream): PGPPublicKeyRing? =
            readPublicKeyRing(inputStream)

    @Throws(IOException::class)
    fun publicKeyRing(bytes: ByteArray): PGPPublicKeyRing? =
            publicKeyRing(bytes.inputStream())

    @Throws(IOException::class)
    fun publicKeyRing(asciiArmored: String): PGPPublicKeyRing? =
            publicKeyRing(asciiArmored.toByteArray(UTF8))

    @Throws(IOException::class)
    fun publicKeyRingCollection(inputStream: InputStream): PGPPublicKeyRingCollection =
            readPublicKeyRingCollection(inputStream)

    @Throws(IOException::class)
    fun publicKeyRingCollection(bytes: ByteArray): PGPPublicKeyRingCollection =
            publicKeyRingCollection(bytes.inputStream())

    @Throws(IOException::class)
    fun publicKeyRingCollection(asciiArmored: String): PGPPublicKeyRingCollection =
            publicKeyRingCollection(asciiArmored.toByteArray(UTF8))

    @Throws(IOException::class)
    fun secretKeyRing(inputStream: InputStream): PGPSecretKeyRing? =
            readSecretKeyRing(inputStream)

    @Throws(IOException::class)
    fun secretKeyRing(bytes: ByteArray): PGPSecretKeyRing? =
            secretKeyRing(bytes.inputStream())

    @Throws(IOException::class)
    fun secretKeyRing(asciiArmored: String): PGPSecretKeyRing? =
            secretKeyRing(asciiArmored.toByteArray(UTF8))

    @Throws(IOException::class)
    fun secretKeyRingCollection(inputStream: InputStream): PGPSecretKeyRingCollection =
            readSecretKeyRingCollection(inputStream)

    @Throws(IOException::class)
    fun secretKeyRingCollection(bytes: ByteArray): PGPSecretKeyRingCollection =
            secretKeyRingCollection(bytes.inputStream())

    @Throws(IOException::class)
    fun secretKeyRingCollection(asciiArmored: String): PGPSecretKeyRingCollection =
            secretKeyRingCollection(asciiArmored.toByteArray(UTF8))

    @Throws(IOException::class)
    fun keyRingCollection(inptStream: InputStream, isSilent: Boolean): PGPKeyRingCollection =
            readKeyRingCollection(inptStream, isSilent)

    @Throws(IOException::class)
    fun keyRingCollection(bytes: ByteArray, isSilent: Boolean): PGPKeyRingCollection =
            keyRingCollection(bytes.inputStream(), isSilent)

    @Throws(IOException::class)
    fun keyRingCollection(asciiArmored: String, isSilent: Boolean): PGPKeyRingCollection =
            keyRingCollection(asciiArmored.toByteArray(UTF8), isSilent)

    companion object {
        private const val MAX_ITERATIONS = 10000

        @JvmStatic
        val UTF8: Charset = charset("UTF8")


        /**
         * Read a [PGPKeyRing] (either [PGPSecretKeyRing] or [PGPPublicKeyRing]) from the given [InputStream].
         * This method will attempt to read at most <pre>maxIterations</pre> objects from the stream before aborting.
         * The first [PGPPublicKeyRing] or [PGPSecretKeyRing] will be returned.
         *
         * @param inputStream inputStream containing the OpenPGP key or certificate
         * @param maxIterations maximum number of objects that are read before the method will abort
         * @return key ring
         * @throws IOException in case of an IO error
         */
        @JvmStatic
        @JvmOverloads
        @Throws(IOException::class)
        fun readKeyRing(inputStream: InputStream,
                        maxIterations: Int = MAX_ITERATIONS): PGPKeyRing? {
            val objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(
                    ArmorUtils.getDecoderStream(inputStream))

            try {
                for ((i, next) in objectFactory.withIndex()) {
                    if (i >= maxIterations) {
                        throw IOException("Loop exceeded max iteration count.")
                    }
                    if (next is PGPMarker) {
                        continue
                    }
                    if (next is PGPSecretKeyRing) {
                        return next
                    }
                    if (next is PGPPublicKeyRing) {
                        return next
                    }
                    continue
                }
            } catch (e : PGPRuntimeOperationException) {
                throw e.cause!!
            }
            return null
        }

        /**
         * Read a public key ring from the provided [InputStream].
         * If more than maxIterations PGP packets are encountered before a [PGPPublicKeyRing] is read,
         * an [IOException] is thrown.
         *
         * @param inputStream input stream
         * @param maxIterations max iterations before abort
         * @return public key ring
         *
         * @throws IOException in case of an IO error or exceeding of max iterations
         */
        @JvmStatic
        @JvmOverloads
        @Throws(IOException::class)
        fun readPublicKeyRing(inputStream: InputStream,
                              maxIterations: Int = MAX_ITERATIONS): PGPPublicKeyRing? {
            val objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(
                    ArmorUtils.getDecoderStream(inputStream))

            try {
                for ((i, next) in objectFactory.withIndex()) {
                    if (i >= maxIterations) {
                        throw IOException("Loop exceeded max iteration count.")
                    }
                    if (next is PGPMarker) {
                        continue
                    }
                    if (next is PGPPublicKeyRing) {
                        return next
                    }
                    continue
                }
            } catch (e : PGPRuntimeOperationException) {
                throw e.cause!!
            }
            return null
        }

        /**
         * Read a public key ring collection from the provided [InputStream].
         * If more than maxIterations PGP packets are encountered before the stream is exhausted,
         * an [IOException] is thrown.
         * If the stream contain secret key packets, their public key parts are extracted and returned.
         *
         * @param inputStream input stream
         * @param maxIterations max iterations before abort
         * @return public key ring collection
         *
         * @throws IOException in case of an IO error or exceeding of max iterations
         */
        @JvmStatic
        @JvmOverloads
        @Throws(IOException::class)
        fun readPublicKeyRingCollection(inputStream: InputStream,
                                        maxIterations: Int = MAX_ITERATIONS): PGPPublicKeyRingCollection {
            val objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(
                    ArmorUtils.getDecoderStream(inputStream))
            val certificates = mutableListOf<PGPPublicKeyRing>()
            try {
                for ((i, next) in objectFactory.withIndex()) {
                    if (i >= maxIterations) {
                        throw IOException("Loop exceeded max iteration count.")
                    }
                    if (next is PGPMarker) {
                        continue
                    }
                    if (next is PGPPublicKeyRing) {
                        certificates.add(next)
                        continue
                    }
                    if (next is PGPSecretKeyRing) {
                        certificates.add(PGPainless.extractCertificate(next))
                        continue
                    }
                    if (next is PGPPublicKeyRingCollection) {
                        certificates.addAll(next)
                        continue
                    }
                }
            } catch (e : PGPRuntimeOperationException) {
                throw e.cause!!
            }
            return PGPPublicKeyRingCollection(certificates)
        }

        /**
         * Read a secret key ring from the provided [InputStream].
         * If more than maxIterations PGP packets are encountered before a [PGPSecretKeyRing] is read,
         * an [IOException] is thrown.
         *
         * @param inputStream input stream
         * @param maxIterations max iterations before abort
         * @return public key ring
         *
         * @throws IOException in case of an IO error or exceeding of max iterations
         */
        @JvmStatic
        @JvmOverloads
        @Throws(IOException::class)
        fun readSecretKeyRing(inputStream: InputStream,
                              maxIterations: Int = MAX_ITERATIONS): PGPSecretKeyRing? {
            val decoderStream = ArmorUtils.getDecoderStream(inputStream)
            val objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(decoderStream)

            try {
                for ((i, next) in objectFactory.withIndex()) {
                    if (i >= maxIterations) {
                        throw IOException("Loop exceeded max iteration count.")
                    }
                    if (next is PGPMarker) {
                        continue
                    }
                    if (next is PGPSecretKeyRing) {
                        Streams.drain(decoderStream)
                        return next
                    }
                }
            } catch (e : PGPRuntimeOperationException) {
                throw e.cause!!
            }
            return null
        }

        /**
         * Read a secret key ring collection from the provided [InputStream].
         * If more than maxIterations PGP packets are encountered before the stream is exhausted,
         * an [IOException] is thrown.
         *
         * @param inputStream input stream
         * @param maxIterations max iterations before abort
         * @return secret key ring collection
         *
         * @throws IOException in case of an IO error or exceeding of max iterations
         */
        @JvmStatic
        @JvmOverloads
        @Throws(IOException::class)
        fun readSecretKeyRingCollection(inputStream: InputStream,
                                        maxIterations: Int = MAX_ITERATIONS): PGPSecretKeyRingCollection {
            val objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(
                    ArmorUtils.getDecoderStream(inputStream))

            val secretKeys = mutableListOf<PGPSecretKeyRing>()
            try {
                for ((i, next) in objectFactory.withIndex()) {
                    if (i >= maxIterations) {
                        throw IOException("Loop exceeded max iteration count.")
                    }
                    if (next is PGPMarker) {
                        continue
                    }
                    if (next is PGPSecretKeyRing) {
                        secretKeys.add(next)
                        continue
                    }
                    if (next is PGPSecretKeyRingCollection) {
                        secretKeys.addAll(next)
                        continue
                    }
                }
            } catch (e : PGPRuntimeOperationException) {
                throw e.cause!!
            }
            return PGPSecretKeyRingCollection(secretKeys)
        }

        @JvmStatic
        @Throws(IOException::class)
        fun readKeyRingCollection(inputStream: InputStream, isSilent: Boolean): PGPKeyRingCollection =
                PGPKeyRingCollection(inputStream, isSilent)
    }

}