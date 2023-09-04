// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>, 2021 Flowcrypt a.s.
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.collection

import org.bouncycastle.openpgp.*
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.util.ArmorUtils
import java.io.InputStream

/**
 * This class describes a logic of handling a collection of different [PGPKeyRing]. The logic was inspired by
 * [PGPSecretKeyRingCollection] and [PGPPublicKeyRingCollection].
 */
class PGPKeyRingCollection(
        val pgpSecretKeyRingCollection: PGPSecretKeyRingCollection,
        val pgpPublicKeyRingCollection: PGPPublicKeyRingCollection
) {

    constructor(encoding: ByteArray, isSilent: Boolean): this(encoding.inputStream(), isSilent)

    constructor(inputStream: InputStream, isSilent: Boolean): this(parse(inputStream, isSilent))

    constructor(collection: Collection<PGPKeyRing>, isSilent: Boolean): this(segment(collection, isSilent))

    private constructor(arguments: Pair<PGPSecretKeyRingCollection, PGPPublicKeyRingCollection>): this(arguments.first, arguments.second)

    /**
     * The number of rings in this collection.
     *
     * @return total size of [PGPSecretKeyRingCollection] plus [PGPPublicKeyRingCollection] in this collection
     */
    val size: Int
        get() = pgpSecretKeyRingCollection.size() + pgpPublicKeyRingCollection.size()

    fun size() = size

    @Deprecated("Wrong case of PGP -> Pgp", ReplaceWith("getPgpSecretKeyRingCollection()"))
    fun getPGPSecretKeyRingCollection() = pgpSecretKeyRingCollection

    companion object {
        @JvmStatic
        private fun parse(inputStream: InputStream, isSilent: Boolean): Pair<PGPSecretKeyRingCollection, PGPPublicKeyRingCollection> {
            val secretKeyRings = mutableListOf<PGPSecretKeyRing>()
            val certificates = mutableListOf<PGPPublicKeyRing>()
            // Double getDecoderStream because of #96
            val objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(ArmorUtils.getDecoderStream(inputStream))

            for (obj in objectFactory) {
                if (obj == null) {
                    break
                }

                if (obj is PGPMarker) {
                    // Skip marker packets
                    continue
                }

                if (obj is PGPSecretKeyRing) {
                    secretKeyRings.add(obj)
                    continue
                }

                if (obj is PGPPublicKeyRing) {
                    certificates.add(obj)
                    continue
                }

                if (!isSilent) {
                    throw PGPException("${obj.javaClass.name} found where ${PGPSecretKeyRing::class.java.simpleName}" +
                            " or ${PGPPublicKeyRing::class.java.simpleName} expected")
                }
            }

            return PGPSecretKeyRingCollection(secretKeyRings) to PGPPublicKeyRingCollection(certificates)
        }

        @JvmStatic
        private fun segment(collection: Collection<PGPKeyRing>, isSilent: Boolean): Pair<PGPSecretKeyRingCollection, PGPPublicKeyRingCollection> {
            val secretKeyRings = mutableListOf<PGPSecretKeyRing>()
            val certificates = mutableListOf<PGPPublicKeyRing>()

            for (keyRing in collection) {
                if (keyRing is PGPSecretKeyRing) {
                    secretKeyRings.add(keyRing)
                } else if (keyRing is PGPPublicKeyRing) {
                    certificates.add(keyRing)
                } else if (!isSilent) {
                    throw PGPException("${keyRing.javaClass.name} found where ${PGPSecretKeyRing::class.java.simpleName}" +
                            " or ${PGPPublicKeyRing::class.java.simpleName} expected")
                }
            }

            return PGPSecretKeyRingCollection(secretKeyRings) to PGPPublicKeyRingCollection(certificates)
        }
    }
}