// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import openpgp.openPgpKeyId
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.UnsupportedPacketVersionException
import org.bouncycastle.extensions.unlock
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory
import org.bouncycastle.util.io.TeeInputStream
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.*
import org.pgpainless.decryption_verification.MessageMetadata.*
import org.pgpainless.decryption_verification.cleartext_signatures.ClearsignedMessageUtil
import org.pgpainless.decryption_verification.syntax_check.InputSymbol
import org.pgpainless.decryption_verification.syntax_check.PDA
import org.pgpainless.decryption_verification.syntax_check.StackSymbol
import org.pgpainless.exception.*
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.key.util.KeyRingUtils
import org.pgpainless.policy.Policy
import org.pgpainless.signature.SignatureUtils
import org.pgpainless.signature.consumer.CertificateValidator
import org.pgpainless.signature.consumer.OnePassSignatureCheck
import org.pgpainless.signature.consumer.SignatureCheck
import org.pgpainless.signature.consumer.SignatureValidator
import org.pgpainless.util.ArmoredInputStreamFactory
import org.pgpainless.util.SessionKey
import org.slf4j.LoggerFactory
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

class OpenPgpMessageInputStream(
        type: Type,
        inputStream: InputStream,
        private val options: ConsumerOptions,
        private val layerMetadata: Layer,
        private val policy: Policy) : DecryptionStream() {

    private val signatures: Signatures = Signatures(options)
    private var packetInputStream: TeeBCPGInputStream? = null
    private var nestedInputStream: InputStream? = null
    private val syntaxVerifier = PDA()
    private var closed = false

    init {

        // Add detached signatures only on the outermost OpenPgpMessageInputStream
        if (layerMetadata is Message) {
            signatures.addDetachedSignatures(options.getDetachedSignatures())
        }

        when(type) {
            Type.standard -> {

                // tee out packet bytes for signature verification
                packetInputStream = TeeBCPGInputStream(BCPGInputStream.wrap(inputStream), signatures)

                // *omnomnom*
                consumePackets()
            }

            Type.cleartext_signed -> {
                val multiPassStrategy = options.getMultiPassStrategy()
                val detachedSignatures = ClearsignedMessageUtil.detachSignaturesFromInbandClearsignedMessage(
                        inputStream, multiPassStrategy.messageOutputStream)

                for (signature in detachedSignatures) {
                    signatures.addDetachedSignature(signature)
                }

                options.isForceNonOpenPgpData()
                nestedInputStream = TeeInputStream(multiPassStrategy.messageInputStream, this.signatures)
            }

            Type.non_openpgp -> {
                packetInputStream = null
                nestedInputStream = TeeInputStream(inputStream, this.signatures)
            }
        }
    }

    enum class Type {
        standard, cleartext_signed, non_openpgp
    }

    constructor(inputStream: InputStream, options: ConsumerOptions, metadata: Layer, policy: Policy):
            this(Type.standard, inputStream, options, metadata, policy)

    private fun consumePackets() {
        val pIn = packetInputStream ?: return

        var packet: OpenPgpPacket?

        // Comsume packets, potentially stepping into nested layers
        layer@ while (run {
                    packet = pIn.nextPacketTag()
                    packet
                } != null) {

            signatures.nextPacket(packet!!)
            // Consume packets in a layer
            when(packet) {

                OpenPgpPacket.LIT -> {
                    processLiteralData()
                    break@layer // nest down
                }

                OpenPgpPacket.COMP -> {
                    processCompressedData()
                    break@layer // nest down
                }

                OpenPgpPacket.OPS -> {
                    processOnePassSignature() // OPS is on the same layer, no nest down
                }

                OpenPgpPacket.SIG -> {
                    processSignature() // SIG is on the same layer, no nest down
                }

                OpenPgpPacket.PKESK, OpenPgpPacket.SKESK, OpenPgpPacket.SED, OpenPgpPacket.SEIPD -> {
                    if (processEncryptedData()) {
                        break@layer
                    }
                    throw MissingDecryptionMethodException("No working decryption method found.")
                }

                OpenPgpPacket.MARKER -> {
                    LOGGER.debug("Skipping Marker Packet")
                    pIn.readMarker()
                }

                OpenPgpPacket.SK, OpenPgpPacket.PK, OpenPgpPacket.SSK, OpenPgpPacket.PSK, OpenPgpPacket.TRUST, OpenPgpPacket.UID, OpenPgpPacket.UATTR ->
                    throw MalformedOpenPgpMessageException("Illegal Packet in Stream: $packet")

                OpenPgpPacket.EXP_1, OpenPgpPacket.EXP_2, OpenPgpPacket.EXP_3, OpenPgpPacket.EXP_4 ->
                    throw MalformedOpenPgpMessageException("Unsupported Packet in Stream: $packet")

                else ->
                    throw MalformedOpenPgpMessageException("Unexpected Packet in Stream: $packet")
            }
        }
    }

    private fun processLiteralData() {
        LOGGER.debug("Literal Data Packet at depth ${layerMetadata.depth} encountered.")
        syntaxVerifier.next(InputSymbol.LITERAL_DATA)
        val literalData = packetInputStream!!.readLiteralData()

        // Extract Metadata
        layerMetadata.child = LiteralData(
                literalData.fileName, literalData.modificationTime,
                StreamEncoding.requireFromCode(literalData.format))

        nestedInputStream = literalData.inputStream
    }

    private fun processCompressedData() {
        syntaxVerifier.next(InputSymbol.COMPRESSED_DATA)
        signatures.enterNesting()
        val compressedData = packetInputStream!!.readCompressedData()

        // Extract Metadata
        val compressionLayer = CompressedData(
                CompressionAlgorithm.requireFromId(compressedData.algorithm),
                layerMetadata.depth + 1)

        LOGGER.debug("Compressed Data Packet (${compressionLayer.algorithm}) at depth ${layerMetadata.depth} encountered.")
        nestedInputStream = OpenPgpMessageInputStream(compressedData.dataStream, options, compressionLayer, policy)
    }

    private fun processOnePassSignature() {
        syntaxVerifier.next(InputSymbol.ONE_PASS_SIGNATURE)
        val ops = packetInputStream!!.readOnePassSignature()
        LOGGER.debug("One-Pass-Signature Packet by key ${ops.keyID.openPgpKeyId()} at depth ${layerMetadata.depth} encountered.")
        signatures.addOnePassSignature(ops)
    }

    private fun processSignature() {
        // true if signature corresponds to OPS
        val isSigForOps = syntaxVerifier.peekStack() == StackSymbol.OPS
        syntaxVerifier.next(InputSymbol.SIGNATURE)
        val signature = try {
            packetInputStream!!.readSignature()
        } catch (e : UnsupportedPacketVersionException) {
            LOGGER.debug("Unsupported Signature at depth ${layerMetadata.depth} encountered.", e)
            return
        }

        val keyId = SignatureUtils.determineIssuerKeyId(signature)
        if (isSigForOps) {
            LOGGER.debug("Signature Packet corresponding to One-Pass-Signature by key ${keyId.openPgpKeyId()} at depth ${layerMetadata.depth} encountered.")
            signatures.leaveNesting() // TODO: Only leave nesting if all OPSs of the nesting layer are dealt with
            signatures.addCorrespondingOnePassSignature(signature, layerMetadata, policy)
        } else {
            LOGGER.debug("Prepended Signature Packet by key ${keyId.openPgpKeyId()} at depth ${layerMetadata.depth} encountered.")
            signatures.addPrependedSignature(signature)
        }
    }

    private fun processEncryptedData(): Boolean {
        LOGGER.debug("Symmetrically Encrypted Data Packet at depth ${layerMetadata.depth} encountered.")
        syntaxVerifier.next(InputSymbol.ENCRYPTED_DATA)
        val encDataList = packetInputStream!!.readEncryptedDataList()
        if (!encDataList.isIntegrityProtected) {
            LOGGER.warn("Symmetrically Encrypted Data Packet is not integrity-protected.")
            if (!options.isIgnoreMDCErrors()) {
                throw MessageNotIntegrityProtectedException()
            }
        }

        val esks = SortedESKs(encDataList)
        LOGGER.debug("Symmetrically Encrypted Integrity-Protected Data has ${esks.skesks.size} SKESK(s) and" +
                " ${esks.pkesks.size + esks.anonPkesks.size} PKESK(s) from which ${esks.anonPkesks.size} PKESK(s)" +
                " have an anonymous recipient.")

        // try custom decryptor factories
        for ((key, decryptorFactory) in options.getCustomDecryptorFactories()) {
            LOGGER.debug("Attempt decryption with custom decryptor factory with key $key.")
            esks.pkesks.filter {
                // find matching PKESK
                it.keyID == key.subkeyId
            }.forEach {
                // attempt decryption
                if (decryptPKESKAndStream(esks, key, decryptorFactory, it)) {
                    return true
                }
            }
        }

        // try provided session key
        if (options.getSessionKey() != null) {
            val sk = options.getSessionKey()!!
            LOGGER.debug("Attempt decryption with provided session key.")
            throwIfUnacceptable(sk.algorithm)

            val decryptorFactory = ImplementationFactory.getInstance()
                    .getSessionKeyDataDecryptorFactory(sk)
            val layer = EncryptedData(sk.algorithm, layerMetadata.depth + 1)
            val skEncData = encDataList.extractSessionKeyEncryptedData()
            try {
                val decrypted = skEncData.getDataStream(decryptorFactory)
                layer.sessionKey = sk
                val integrityProtected = IntegrityProtectedInputStream(decrypted, skEncData, options)
                nestedInputStream = OpenPgpMessageInputStream(integrityProtected, options, layer, policy)
                LOGGER.debug("Successfully decrypted data using provided session key")
                return true
            } catch (e : PGPException) {
                // Session key mismatch?
                LOGGER.debug("Decryption using provided session key failed. Mismatched session key and message?", e)
            }
        }

        // try passwords
        for (passphrase in options.getDecryptionPassphrases()) {
            for (skesk in esks.skesks) {
                LOGGER.debug("Attempt decryption with provided passphrase")
                val algorithm = SymmetricKeyAlgorithm.requireFromId(skesk.algorithm)
                if (!isAcceptable(algorithm)) {
                    LOGGER.debug("Skipping SKESK with unacceptable encapsulation algorithm $algorithm")
                    continue
                }

                val decryptorFactory = ImplementationFactory.getInstance()
                        .getPBEDataDecryptorFactory(passphrase)
                if (decryptSKESKAndStream(esks, skesk, decryptorFactory)) {
                    return true
                }
            }
        }

        val postponedDueToMissingPassphrase = mutableListOf<Pair<PGPSecretKey, PGPPublicKeyEncryptedData>>()

        // try (known) secret keys
        for (pkesk in esks.pkesks) {
            val keyId = pkesk.keyID
            LOGGER.debug("Encountered PKESK for recipient ${keyId.openPgpKeyId()}")
            val decryptionKeys = getDecryptionKey(keyId)
            if (decryptionKeys == null) {
                LOGGER.debug("Skipping PKESK because no matching key ${keyId.openPgpKeyId()} was provided.")
                continue
            }
            val secretKey = decryptionKeys.getSecretKey(keyId)
            val decryptionKeyId = SubkeyIdentifier(decryptionKeys, keyId)
            if (hasUnsupportedS2KSpecifier(secretKey, decryptionKeyId)) {
                continue
            }

            LOGGER.debug("Attempt decryption using secret key $decryptionKeyId")
            val protector = options.getSecretKeyProtector(decryptionKeys) ?: continue
            if (!protector.hasPassphraseFor(keyId)) {
                LOGGER.debug("Missing passphrase for key $decryptionKeyId. Postponing decryption until all other keys were tried.")
                postponedDueToMissingPassphrase.add(secretKey to pkesk)
                continue
            }

            val privateKey = secretKey.unlock(protector)
            if (decryptWithPrivateKey(esks, privateKey, decryptionKeyId, pkesk)) {
                return true
            }
        }

        // try anonymous secret keys
        for (pkesk in esks.anonPkesks) {
            for ((decryptionKeys, secretKey) in findPotentialDecryptionKeys(pkesk)) {
                val decryptionKeyId = SubkeyIdentifier(decryptionKeys, secretKey.keyID)
                if (hasUnsupportedS2KSpecifier(secretKey, decryptionKeyId)) {
                    continue
                }

                LOGGER.debug("Attempt decryption of anonymous PKESK with key $decryptionKeyId.")
                val protector = options.getSecretKeyProtector(decryptionKeys) ?: continue

                if (!protector.hasPassphraseFor(secretKey.keyID)) {
                    LOGGER.debug("Missing passphrase for key $decryptionKeyId. Postponing decryption until all other keys were tried.")
                    postponedDueToMissingPassphrase.add(secretKey to pkesk)
                    continue
                }

                val privateKey = secretKey.unlock(protector)
                if (decryptWithPrivateKey(esks, privateKey, decryptionKeyId, pkesk)) {
                    return true
                }
            }
        }

        if (options.getMissingKeyPassphraseStrategy() == MissingKeyPassphraseStrategy.THROW_EXCEPTION) {
            // Non-interactive mode: Throw an exception with all locked decryption keys
            postponedDueToMissingPassphrase.map {
                SubkeyIdentifier(getDecryptionKey(it.first.keyID)!!, it.first.keyID)
            }.also {
                if (it.isNotEmpty())
                    throw MissingPassphraseException(it.toSet())
            }
        } else if (options.getMissingKeyPassphraseStrategy() == MissingKeyPassphraseStrategy.INTERACTIVE) {
            for ((secretKey, pkesk) in postponedDueToMissingPassphrase) {
                val keyId = secretKey.keyID
                val decryptionKeys = getDecryptionKey(keyId)!!
                val decryptionKeyId = SubkeyIdentifier(decryptionKeys, keyId)
                if (hasUnsupportedS2KSpecifier(secretKey, decryptionKeyId)) {
                    continue
                }

                LOGGER.debug("Attempt decryption with key $decryptionKeyId while interactively requesting its passphrase.")
                val protector = options.getSecretKeyProtector(decryptionKeys) ?: continue
                val privateKey = secretKey.unlock(protector)
                if (decryptWithPrivateKey(esks, privateKey, decryptionKeyId, pkesk)) {
                    return true
                }
            }
        } else {
            throw IllegalStateException("Invalid PostponedKeysStrategy set in consumer options.")
        }

        // We did not yet succeed in decrypting any session key :/
        LOGGER.debug("Failed to decrypt encrypted data packet.")
        return false
    }

    private fun decryptWithPrivateKey(esks: SortedESKs,
                                      privateKey: PGPPrivateKey,
                                      decryptionKeyId: SubkeyIdentifier,
                                      pkesk: PGPPublicKeyEncryptedData): Boolean {
        val decryptorFactory = ImplementationFactory.getInstance()
                .getPublicKeyDataDecryptorFactory(privateKey)
        return decryptPKESKAndStream(esks, decryptionKeyId, decryptorFactory, pkesk)
    }

    private fun hasUnsupportedS2KSpecifier(secretKey: PGPSecretKey, decryptionKeyId: SubkeyIdentifier): Boolean {
        val s2k = secretKey.s2K
        if (s2k != null) {
            if (s2k.type in 100..110) {
                LOGGER.debug("Skipping PKESK because key $decryptionKeyId has unsupported private S2K specifier ${s2k.type}")
                return true
            }
        }
        return false
    }

    private fun decryptSKESKAndStream(esks: SortedESKs,
                                      skesk: PGPPBEEncryptedData,
                                      decryptorFactory: PBEDataDecryptorFactory): Boolean {
        try {
            val decrypted = skesk.getDataStream(decryptorFactory)
            val sessionKey = SessionKey(skesk.getSessionKey(decryptorFactory))
            throwIfUnacceptable(sessionKey.algorithm)
            val encryptedData = EncryptedData(sessionKey.algorithm, layerMetadata.depth + 1)
            encryptedData.sessionKey = sessionKey
            encryptedData.addRecipients(esks.pkesks.map { it.keyID })
            LOGGER.debug("Successfully decrypted data with passphrase")
            val integrityProtected = IntegrityProtectedInputStream(decrypted, skesk, options)
            nestedInputStream = OpenPgpMessageInputStream(integrityProtected, options, encryptedData, policy)
            return true
        } catch (e : UnacceptableAlgorithmException) {
            throw e
        } catch (e : PGPException) {
            LOGGER.debug("Decryption of encrypted data packet using password failed. Password mismatch?", e)
        }
        return false
    }

    private fun decryptPKESKAndStream(esks: SortedESKs,
                                      decryptionKeyId: SubkeyIdentifier,
                                      decryptorFactory: PublicKeyDataDecryptorFactory,
                                      pkesk: PGPPublicKeyEncryptedData): Boolean {
        try {
            val decrypted = pkesk.getDataStream(decryptorFactory)
            val sessionKey = SessionKey(pkesk.getSessionKey(decryptorFactory))
            throwIfUnacceptable(sessionKey.algorithm)

            val encryptedData = EncryptedData(
                    SymmetricKeyAlgorithm.requireFromId(pkesk.getSymmetricAlgorithm(decryptorFactory)),
                    layerMetadata.depth + 1)
            encryptedData.decryptionKey = decryptionKeyId
            encryptedData.sessionKey = sessionKey
            encryptedData.addRecipients(esks.pkesks.plus(esks.anonPkesks).map { it.keyID })
            LOGGER.debug("Successfully decrypted data with key $decryptionKeyId")
            val integrityProtected = IntegrityProtectedInputStream(decrypted, pkesk, options)
            nestedInputStream = OpenPgpMessageInputStream(integrityProtected, options, encryptedData, policy)
            return true
        } catch (e : UnacceptableAlgorithmException) {
            throw e
        } catch (e : PGPException) {
            LOGGER.debug("Decryption of encrypted data packet using secret key failed.", e)
        }
        return false
    }

    override fun read(): Int {
        if (nestedInputStream == null) {
            if (packetInputStream != null) {
                syntaxVerifier.assertValid()
            }
            return -1
        }

        val r: Int = try {
            nestedInputStream!!.read()
        } catch (e: IOException) {
            -1
        }
        if (r != -1) {
            signatures.updateLiteral(r.toByte())
        } else {
            nestedInputStream!!.close()
            collectMetadata()
            nestedInputStream = null
            if (packetInputStream != null) {
                try {
                    consumePackets()
                } catch (e: PGPException) {
                    throw RuntimeException(e)
                }
            }
            signatures.finish(layerMetadata, policy)
        }
        return r
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (nestedInputStream == null) {
            if (packetInputStream != null) {
                syntaxVerifier.next(InputSymbol.END_OF_SEQUENCE)
                syntaxVerifier.assertValid()
            }
            return -1
        }
        val r = nestedInputStream!!.read(b, off, len)
        if (r != -1) {
            signatures.updateLiteral(b, off, r)
        } else {
            nestedInputStream!!.close()
            collectMetadata()
            nestedInputStream = null
            if (packetInputStream != null) {
                try {
                    consumePackets()
                } catch (e: PGPException) {
                    throw RuntimeException(e)
                }
            }
            signatures.finish(layerMetadata, policy)
        }
        return r
    }

    override fun close() {
        super.close()
        if (closed) {
            if (packetInputStream != null) {
                syntaxVerifier.next(InputSymbol.END_OF_SEQUENCE)
                syntaxVerifier.assertValid()
            }
            return
        }
        if (nestedInputStream != null) {
            nestedInputStream!!.close()
            collectMetadata()
            nestedInputStream = null
        }
        try {
            consumePackets()
        } catch (e: PGPException) {
            throw RuntimeException(e)
        }
        if (packetInputStream != null) {
            syntaxVerifier.next(InputSymbol.END_OF_SEQUENCE)
            syntaxVerifier.assertValid()
            packetInputStream!!.close()
        }
        closed = true
    }

    private fun collectMetadata() {
        if (nestedInputStream is OpenPgpMessageInputStream) {
            val child = nestedInputStream as OpenPgpMessageInputStream
            layerMetadata.child = (child.layerMetadata as Nested)
        }
    }

    override val metadata: MessageMetadata
        get() {
            check(closed) { "Stream must be closed before access to metadata can be granted." }

            return MessageMetadata((layerMetadata as Message))
        }

    private fun getDecryptionKey(keyId: Long): PGPSecretKeyRing? = options.getDecryptionKeys().firstOrNull {
        it.any {
            k -> k.keyID == keyId
        }.and(PGPainless.inspectKeyRing(it).decryptionSubkeys.any {
            k -> k.keyID == keyId
        })
    }

    private fun findPotentialDecryptionKeys(pkesk: PGPPublicKeyEncryptedData): List<Pair<PGPSecretKeyRing, PGPSecretKey>> {
        val algorithm = pkesk.algorithm
        val candidates = mutableListOf<Pair<PGPSecretKeyRing, PGPSecretKey>>()
        options.getDecryptionKeys().forEach {
            val info = PGPainless.inspectKeyRing(it)
            for (key in info.decryptionSubkeys) {
                if (key.algorithm == algorithm && info.isSecretKeyAvailable(key.keyID)) {
                    candidates.add(it to it.getSecretKey(key.keyID))
                }
            }
        }
        return candidates
    }

    private fun isAcceptable(algorithm: SymmetricKeyAlgorithm): Boolean =
            policy.symmetricKeyDecryptionAlgorithmPolicy.isAcceptable(algorithm)

    private fun throwIfUnacceptable(algorithm: SymmetricKeyAlgorithm) {
        if (!isAcceptable(algorithm)) {
            throw UnacceptableAlgorithmException("Symmetric-Key algorithm $algorithm is not acceptable for message decryption.")
        }
    }

    private class SortedESKs(esks: PGPEncryptedDataList) {
        val skesks: List<PGPPBEEncryptedData>
        val pkesks: List<PGPPublicKeyEncryptedData>
        val anonPkesks: List<PGPPublicKeyEncryptedData>

        init {
            skesks = mutableListOf()
            pkesks = mutableListOf()
            anonPkesks = mutableListOf()
            for (esk in esks) {
                if (esk is PGPPBEEncryptedData) {
                    skesks.add(esk)
                } else if (esk is PGPPublicKeyEncryptedData) {
                    if (esk.keyID != 0L) {
                        pkesks.add(esk)
                    } else {
                        anonPkesks.add(esk)
                    }
                } else {
                    throw IllegalArgumentException("Unknown ESK class type ${esk.javaClass}")
                }
            }
        }

        val all: List<PGPEncryptedData>
            get() = skesks.plus(pkesks).plus(anonPkesks)
    }

    private class Signatures(
            val options: ConsumerOptions
    ) : OutputStream() {
        val detachedSignatures = mutableListOf<SignatureCheck>()
        val prependedSignatures = mutableListOf<SignatureCheck>()
        val onePassSignatures = mutableListOf<OnePassSignatureCheck>()
        val opsUpdateStack = ArrayDeque<MutableList<OnePassSignatureCheck>>()
        var literalOPS = mutableListOf<OnePassSignatureCheck>()
        val correspondingSignatures = mutableListOf<PGPSignature>()
        val prependedSignaturesWithMissingCert = mutableListOf<SignatureVerification.Failure>()
        val inbandSignaturesWithMissingCert = mutableListOf<SignatureVerification.Failure>()
        val detachedSignaturesWithMissingCert = mutableListOf<SignatureVerification.Failure>()
        var isLiteral = true

        fun addDetachedSignatures(signatures: Collection<PGPSignature>) {
            for (signature in signatures) {
                addDetachedSignature(signature)
            }
        }

        fun addDetachedSignature(signature: PGPSignature) {
            val check = initializeSignature(signature)
            val keyId = SignatureUtils.determineIssuerKeyId(signature)
            if (check != null) {
                detachedSignatures.add(check)
            } else {
                LOGGER.debug("No suitable certificate for verification of signature by key ${keyId.openPgpKeyId()} found.")
                detachedSignaturesWithMissingCert.add(SignatureVerification.Failure(
                        signature, null, SignatureValidationException("Missing verification key.")))
            }
        }

        fun addPrependedSignature(signature: PGPSignature) {
            val check = initializeSignature(signature)
            val keyId = SignatureUtils.determineIssuerKeyId(signature)
            if (check != null) {
                prependedSignatures.add(check)
            } else {
                LOGGER.debug("No suitable certificate for verification of signature by key ${keyId.openPgpKeyId()} found.")
                prependedSignaturesWithMissingCert.add(SignatureVerification.Failure(
                        signature, null, SignatureValidationException("Missing verification key")
                ))
            }
        }

        fun initializeSignature(signature: PGPSignature): SignatureCheck? {
            val keyId = SignatureUtils.determineIssuerKeyId(signature)
            val certificate = findCertificate(keyId) ?: return null

            val verifierKey = SubkeyIdentifier(certificate, keyId)
            initialize(signature, certificate, keyId)
            return SignatureCheck(signature, certificate, verifierKey)
        }

        fun addOnePassSignature(signature: PGPOnePassSignature) {
            val certificate = findCertificate(signature.keyID)

            if (certificate != null) {
                val ops = OnePassSignatureCheck(signature, certificate)
                initialize(signature, certificate)
                onePassSignatures.add(ops)
                literalOPS.add(ops)
            }
            if (signature.isContaining) {
                enterNesting()
            }
        }

        fun addCorrespondingOnePassSignature(signature: PGPSignature, layer: Layer, policy: Policy) {
            var found = false
            val keyId = SignatureUtils.determineIssuerKeyId(signature)
            for ((i, check) in onePassSignatures.withIndex().reversed()) {
                if (check.onePassSignature.keyID != keyId) {
                    continue
                }
                found = true

                if (check.signature != null) {
                    continue
                }

                check.signature = signature
                val verification = SignatureVerification(signature,
                        SubkeyIdentifier(check.verificationKeys, check.onePassSignature.keyID))

                try {
                    SignatureValidator.signatureWasCreatedInBounds(options.getVerifyNotBefore(), options.getVerifyNotAfter())
                            .verify(signature)
                    CertificateValidator.validateCertificateAndVerifyOnePassSignature(check, policy)
                    LOGGER.debug("Acceptable signature by key ${verification.signingKey}")
                    layer.addVerifiedOnePassSignature(verification)
                } catch (e: SignatureValidationException) {
                    LOGGER.debug("Rejected signature by key ${verification.signingKey}", e)
                    layer.addRejectedOnePassSignature(SignatureVerification.Failure(verification, e))
                }
                break
            }

            if (!found) {
                LOGGER.debug("No suitable certificate for verification of signature by key ${keyId.openPgpKeyId()} found.")
                inbandSignaturesWithMissingCert.add(SignatureVerification.Failure(
                        signature, null, SignatureValidationException("Missing verification key.")
                ))
            }
        }

        fun enterNesting() {
            opsUpdateStack.addFirst(literalOPS)
            literalOPS = mutableListOf()
        }

        fun leaveNesting() {
            if (opsUpdateStack.isEmpty()) {
                return
            }
            opsUpdateStack.removeFirst()
        }

        fun findCertificate(keyId: Long): PGPPublicKeyRing? {
            val cert = options.getCertificateSource().getCertificate(keyId)
            if (cert != null) {
                return cert
            }

            if (options.getMissingCertificateCallback() != null) {
                return options.getMissingCertificateCallback()!!.onMissingPublicKeyEncountered(keyId)
            }
            return null // TODO: Missing cert for sig
        }

        fun updateLiteral(b: Byte) {
            for (ops in literalOPS) {
                ops.onePassSignature.update(b)
            }

            for (detached in detachedSignatures) {
                detached.signature.update(b)
            }

            for (prepended in prependedSignatures) {
                prepended.signature.update(b)
            }
        }

        fun updateLiteral(buf: ByteArray, off: Int, len: Int) {
            for (ops in literalOPS) {
                ops.onePassSignature.update(buf, off, len)
            }

            for (detached in detachedSignatures) {
                detached.signature.update(buf, off, len)
            }

            for (prepended in prependedSignatures) {
                prepended.signature.update(buf, off, len)
            }
        }

        fun updatePacket(b: Byte) {
            for (nestedOPSs in opsUpdateStack.reversed()) {
                for (ops in nestedOPSs) {
                    ops.onePassSignature.update(b)
                }
            }
        }

        fun updatePacket(buf: ByteArray, off: Int, len: Int) {
            for (nestedOPSs in opsUpdateStack.reversed()) {
                for (ops in nestedOPSs) {
                    ops.onePassSignature.update(buf, off, len)
                }
            }
        }

        fun finish(layer: Layer, policy: Policy) {
            for (detached in detachedSignatures) {
                val verification = SignatureVerification(detached.signature, detached.signingKeyIdentifier)
                try {
                    SignatureValidator.signatureWasCreatedInBounds(options.getVerifyNotBefore(), options.getVerifyNotAfter())
                            .verify(detached.signature)
                    CertificateValidator.validateCertificateAndVerifyInitializedSignature(
                            detached.signature, KeyRingUtils.publicKeys(detached.signingKeyRing), policy)
                    LOGGER.debug("Acceptable signature by key ${verification.signingKey}")
                    layer.addVerifiedDetachedSignature(verification)
                } catch (e : SignatureValidationException) {
                    LOGGER.debug("Rejected signature by key ${verification.signingKey}", e)
                    layer.addRejectedDetachedSignature(SignatureVerification.Failure(verification, e))
                }
            }

            for (prepended in prependedSignatures) {
                val verification = SignatureVerification(prepended.signature, prepended.signingKeyIdentifier)
                try {
                    SignatureValidator.signatureWasCreatedInBounds(options.getVerifyNotBefore(), options.getVerifyNotAfter())
                            .verify(prepended.signature)
                    CertificateValidator.validateCertificateAndVerifyInitializedSignature(
                            prepended.signature, KeyRingUtils.publicKeys(prepended.signingKeyRing), policy)
                    LOGGER.debug("Acceptable signature by key ${verification.signingKey}")
                    layer.addVerifiedPrependedSignature(verification)
                } catch (e : SignatureValidationException) {
                    LOGGER.debug("Rejected signature by key ${verification.signingKey}", e)
                    layer.addRejectedPrependedSignature(SignatureVerification.Failure(verification, e))
                }
            }

            for (rejected in inbandSignaturesWithMissingCert) {
                layer.addRejectedOnePassSignature(rejected)
            }

            for (rejected in prependedSignaturesWithMissingCert) {
                layer.addRejectedPrependedSignature(rejected)
            }

            for (rejected in detachedSignaturesWithMissingCert) {
                layer.addRejectedDetachedSignature(rejected)
            }
        }

        override fun write(b: Int) {
            updatePacket(b.toByte())
        }

        override fun write(buf: ByteArray, off: Int, len: Int) {
            updatePacket(buf, off, len)
        }

        fun nextPacket(nextPacket: OpenPgpPacket) {
            if (nextPacket == OpenPgpPacket.LIT) {
                isLiteral = true
                if (literalOPS.isEmpty() && opsUpdateStack.isNotEmpty()) {
                    literalOPS = opsUpdateStack.removeFirst()
                }
            } else {
                isLiteral = false
            }
        }

        companion object {
            @JvmStatic
            private fun initialize(signature: PGPSignature, certificate: PGPPublicKeyRing, keyId: Long) {
                val verifierProvider = ImplementationFactory.getInstance()
                        .pgpContentVerifierBuilderProvider
                try {
                    signature.init(verifierProvider, certificate.getPublicKey(keyId))
                } catch (e : PGPException) {
                    throw RuntimeException(e)
                }
            }

            @JvmStatic
            private fun initialize(ops: PGPOnePassSignature, certificate: PGPPublicKeyRing) {
                val verifierProvider = ImplementationFactory.getInstance()
                        .pgpContentVerifierBuilderProvider
                try {
                    ops.init(verifierProvider, certificate.getPublicKey(ops.keyID))
                } catch (e : PGPException) {
                    throw RuntimeException(e)
                }
            }
        }
    }

    companion object {
        @JvmStatic
        private val LOGGER = LoggerFactory.getLogger(OpenPgpMessageInputStream::class.java)

        @JvmStatic
        fun create(inputStream: InputStream,
                   options: ConsumerOptions) = create(inputStream, options, PGPainless.getPolicy())

        @JvmStatic
        fun create(inputStream: InputStream,
                   options: ConsumerOptions,
                   policy: Policy) = create(inputStream, options, Message(), policy)

        @JvmStatic
        internal fun create(inputStream: InputStream,
                            options: ConsumerOptions,
                            metadata: Layer,
                            policy: Policy): OpenPgpMessageInputStream {
            val openPgpIn = OpenPgpInputStream(inputStream)
            openPgpIn.reset()

            if (openPgpIn.isNonOpenPgp || options.isForceNonOpenPgpData()) {
                return OpenPgpMessageInputStream(Type.non_openpgp, openPgpIn, options, metadata, policy)
            }

            if (openPgpIn.isBinaryOpenPgp) {
                // Simply consume OpenPGP message
                return OpenPgpMessageInputStream(Type.standard, openPgpIn, options, metadata, policy)
            }

            return if (openPgpIn.isAsciiArmored) {
                val armorIn = ArmoredInputStreamFactory.get(openPgpIn)
                if (armorIn.isClearText) {
                    (metadata as Message).setCleartextSigned()
                    OpenPgpMessageInputStream(Type.cleartext_signed, armorIn, options, metadata, policy)
                } else {
                    // Simply consume dearmored OpenPGP message
                    OpenPgpMessageInputStream(Type.standard, armorIn, options, metadata, policy)
                }
            } else {
                throw AssertionError("Cannot deduce type of data.")
            }
        }
    }
}