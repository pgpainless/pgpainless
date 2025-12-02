// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream
import openpgp.openPgpKeyId
import org.bouncycastle.bcpg.AEADEncDataPacket
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket
import org.bouncycastle.bcpg.UnsupportedPacketVersionException
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPOnePassSignature
import org.bouncycastle.openpgp.PGPPBEEncryptedData
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureException
import org.bouncycastle.openpgp.api.EncryptedDataPacketType
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPPrivateKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPSecretKey
import org.bouncycastle.openpgp.api.OpenPGPSignature.OpenPGPDocumentSignature
import org.bouncycastle.openpgp.api.exception.MalformedOpenPGPSignatureException
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.util.io.TeeInputStream
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.OpenPgpPacket
import org.pgpainless.algorithm.StreamEncoding
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.bouncycastle.extensions.assertCreatedInBounds
import org.pgpainless.bouncycastle.extensions.getSecretKeyFor
import org.pgpainless.bouncycastle.extensions.getSigningKeyFor
import org.pgpainless.bouncycastle.extensions.issuerKeyId
import org.pgpainless.decryption_verification.MessageMetadata.CompressedData
import org.pgpainless.decryption_verification.MessageMetadata.EncryptedData
import org.pgpainless.decryption_verification.MessageMetadata.Layer
import org.pgpainless.decryption_verification.MessageMetadata.LiteralData
import org.pgpainless.decryption_verification.MessageMetadata.Message
import org.pgpainless.decryption_verification.MessageMetadata.Nested
import org.pgpainless.decryption_verification.cleartext_signatures.ClearsignedMessageUtil
import org.pgpainless.decryption_verification.syntax_check.InputSymbol
import org.pgpainless.decryption_verification.syntax_check.PDA
import org.pgpainless.decryption_verification.syntax_check.StackSymbol
import org.pgpainless.exception.MalformedOpenPgpMessageException
import org.pgpainless.exception.MessageNotIntegrityProtectedException
import org.pgpainless.exception.MissingDecryptionMethodException
import org.pgpainless.exception.MissingPassphraseException
import org.pgpainless.exception.SignatureValidationException
import org.pgpainless.exception.UnacceptableAlgorithmException
import org.pgpainless.exception.WrongPassphraseException
import org.pgpainless.hardware.HardwareTokenBackend
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.key.protection.UnlockSecretKey.Companion.unlockSecretKey
import org.pgpainless.signature.consumer.OnePassSignatureCheck
import org.pgpainless.util.ArmoredInputStreamFactory
import org.pgpainless.util.SessionKey
import org.slf4j.LoggerFactory

class OpenPgpMessageInputStream(
    type: Type,
    inputStream: InputStream,
    private val options: ConsumerOptions,
    private val layerMetadata: Layer,
    private val api: PGPainless
) : DecryptionStream() {

    private val signatures: Signatures = Signatures(options, api)
    private var packetInputStream: TeeBCPGInputStream? = null
    private var nestedInputStream: InputStream? = null
    private val syntaxVerifier = PDA()
    private var closed = false

    init {

        // Add detached signatures only on the outermost OpenPgpMessageInputStream
        if (layerMetadata is Message) {
            signatures.addDetachedSignatures(options.getDetachedSignatures())
        }

        when (type) {
            Type.standard -> {

                // tee out packet bytes for signature verification
                packetInputStream =
                    TeeBCPGInputStream(BCPGInputStream.wrap(inputStream), signatures)

                // *omnomnom*
                consumePackets()
            }
            Type.cleartext_signed -> {
                val multiPassStrategy = options.getMultiPassStrategy()
                val detachedSignatures =
                    ClearsignedMessageUtil.detachSignaturesFromInbandClearsignedMessage(
                        inputStream, multiPassStrategy.messageOutputStream)

                for (signature in detachedSignatures) {
                    signatures.addDetachedSignature(signature)
                }

                options.isForceNonOpenPgpData()
                nestedInputStream =
                    TeeInputStream(multiPassStrategy.messageInputStream, this.signatures)
            }
            Type.non_openpgp -> {
                packetInputStream = null
                nestedInputStream = TeeInputStream(inputStream, this.signatures)
            }
        }
    }

    enum class Type {
        standard,
        cleartext_signed,
        non_openpgp
    }

    constructor(
        inputStream: InputStream,
        options: ConsumerOptions,
        metadata: Layer,
        api: PGPainless
    ) : this(Type.standard, inputStream, options, metadata, api)

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
            when (packet) {
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
                OpenPgpPacket.PKESK,
                OpenPgpPacket.SKESK,
                OpenPgpPacket.SED,
                OpenPgpPacket.SEIPD,
                OpenPgpPacket.OED -> {
                    if (processEncryptedData()) {
                        break@layer
                    }
                    throw MissingDecryptionMethodException("No working decryption method found.")
                }
                OpenPgpPacket.MARKER -> {
                    LOGGER.debug("Skipping Marker Packet")
                    pIn.readMarker()
                }
                OpenPgpPacket.PADDING -> {
                    LOGGER.debug("Skipping Padding Packet")
                    pIn.readPadding()
                }
                OpenPgpPacket.SK,
                OpenPgpPacket.PK,
                OpenPgpPacket.SSK,
                OpenPgpPacket.PSK,
                OpenPgpPacket.TRUST,
                OpenPgpPacket.UID,
                OpenPgpPacket.UATTR ->
                    throw MalformedOpenPgpMessageException("Illegal Packet in Stream: $packet")
                OpenPgpPacket.EXP_1,
                OpenPgpPacket.EXP_2,
                OpenPgpPacket.EXP_3,
                OpenPgpPacket.EXP_4 ->
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
        layerMetadata.child =
            LiteralData(
                literalData.fileName,
                literalData.modificationTime,
                StreamEncoding.requireFromCode(literalData.format))

        nestedInputStream = literalData.inputStream
    }

    private fun processCompressedData() {
        syntaxVerifier.next(InputSymbol.COMPRESSED_DATA)
        signatures.enterNesting()
        val compressedData = packetInputStream!!.readCompressedData()

        // Extract Metadata
        val compressionLayer =
            CompressedData(
                CompressionAlgorithm.requireFromId(compressedData.algorithm),
                layerMetadata.depth + 1)

        LOGGER.debug(
            "Compressed Data Packet (${compressionLayer.algorithm}) at depth ${layerMetadata.depth} encountered.")
        nestedInputStream =
            OpenPgpMessageInputStream(decompress(compressedData), options, compressionLayer, api)
    }

    private fun decompress(compressedData: PGPCompressedData): InputStream {
        return when (compressedData.algorithm) {
            CompressionAlgorithmTags.ZIP ->
                object : InflaterInputStream(compressedData.inputStream, Inflater(true)) {
                    private var eof = false

                    override fun fill() {
                        if (eof) {
                            throw EOFException("Unexpected end of ZIP input stream")
                        }

                        len = `in`.read(buf, 0, buf.size)

                        if (len == -1) {
                            buf[0] = 0
                            len = 0
                            eof = true
                        }

                        inf.setInput(buf, 0, len)
                    }
                }
            CompressionAlgorithmTags.ZLIB ->
                object : InflaterInputStream(compressedData.inputStream) {
                    private var eof = false

                    override fun fill() {
                        if (eof) {
                            throw EOFException("Unexpected end of ZIP input stream")
                        }

                        len = `in`.read(buf, 0, buf.size)

                        if (len == -1) {
                            buf[0] = 0
                            len = 0
                            eof = true
                        }

                        inf.setInput(buf, 0, len)
                    }
                }
            else -> compressedData.dataStream
        }
    }

    private fun processOnePassSignature() {
        syntaxVerifier.next(InputSymbol.ONE_PASS_SIGNATURE)
        val ops =
            try {
                packetInputStream!!.readOnePassSignature()
            } catch (e: UnsupportedPacketVersionException) {
                LOGGER.debug("Unsupported One-Pass-Signature packet version encountered.", e)
                return
            }
        signatures.addOnePassSignature(ops)
    }

    private fun processSignature() {
        // true if signature corresponds to OPS
        val isSigForOps = syntaxVerifier.peekStack() == StackSymbol.OPS
        syntaxVerifier.next(InputSymbol.SIGNATURE)
        val signature =
            try {
                packetInputStream!!.readSignature()
            } catch (e: UnsupportedPacketVersionException) {
                LOGGER.debug(
                    "Unsupported Signature at depth ${layerMetadata.depth} encountered.", e)
                return
            }

        val keyId = signature.issuerKeyId
        if (isSigForOps) {
            LOGGER.debug(
                "Signature Packet corresponding to One-Pass-Signature by key ${keyId.openPgpKeyId()} at depth ${layerMetadata.depth} encountered.")
            signatures
                .leaveNesting() // TODO: Only leave nesting if all OPSs of the nesting layer are
            // dealt with
            signatures.addCorrespondingOnePassSignature(signature, layerMetadata)
        } else {
            LOGGER.debug(
                "Prepended Signature Packet by key ${keyId.openPgpKeyId()} at depth ${layerMetadata.depth} encountered.")
            signatures.addPrependedSignature(signature)
        }
    }

    private fun processEncryptedData(): Boolean {
        // TODO: Replace by dedicated encryption packet type input symbols
        syntaxVerifier.next(InputSymbol.ENCRYPTED_DATA)

        val encDataList = packetInputStream!!.readEncryptedDataList()
        val esks = ESKsAndData(encDataList)

        when (EncryptedDataPacketType.of(encDataList)!!) {
            EncryptedDataPacketType.SEIPDv2 ->
                LOGGER.debug(
                    "Symmetrically Encrypted Integrity Protected Data Packet version 2 at depth " +
                        "${layerMetadata.depth} encountered.")
            EncryptedDataPacketType.SEIPDv1 ->
                LOGGER.debug(
                    "Symmetrically Encrypted Integrity Protected Data Packet version 1 at depth " +
                        "${layerMetadata.depth} encountered.")
            EncryptedDataPacketType.LIBREPGP_OED ->
                LOGGER.debug(
                    "LibrePGP OCB-Encrypted Data Packet at depth " +
                        "${layerMetadata.depth} encountered.")
            EncryptedDataPacketType.SED -> {
                LOGGER.debug(
                    "(Deprecated) Symmetrically Encrypted Data Packet at depth " +
                        "${layerMetadata.depth} encountered.")
                LOGGER.warn("Symmetrically Encrypted Data Packet is not integrity-protected.")
                if (!options.isIgnoreMDCErrors()) {
                    throw MessageNotIntegrityProtectedException()
                }
            }
        }

        LOGGER.debug(
            "Encrypted Data has ${esks.skesks.size} SKESK(s) and" +
                " ${esks.pkesks.size + esks.anonPkesks.size} PKESK(s) from which ${esks.anonPkesks.size} PKESK(s)" +
                " have an anonymous recipient.")

        // try custom decryptor factories
        for ((key, decryptorFactory) in options.getCustomDecryptorFactories()) {
            LOGGER.debug("Attempt decryption with custom decryptor factory with key $key.")
            esks.pkesks
                .filter {
                    // find matching PKESK
                    it.keyIdentifier == key.keyIdentifier
                }
                .forEach {
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

            val pgpSk = PGPSessionKey(sk.algorithm.algorithmId, sk.key)
            val decryptorFactory = api.implementation.sessionKeyDataDecryptorFactory(pgpSk)
            val layer = esks.toEncryptedData(sk, layerMetadata.depth + 1)
            val skEncData = encDataList.extractSessionKeyEncryptedData()
            try {
                val decrypted = skEncData.getDataStream(decryptorFactory)
                layer.sessionKey = sk
                val integrityProtected =
                    IntegrityProtectedInputStream(decrypted, skEncData, options)
                nestedInputStream =
                    OpenPgpMessageInputStream(integrityProtected, options, layer, api)
                LOGGER.debug("Successfully decrypted data using provided session key")
                return true
            } catch (e: PGPException) {
                // Session key mismatch?
                LOGGER.debug(
                    "Decryption using provided session key failed. Mismatched session key and message?",
                    e)
            }
        }

        // try passwords
        for (passphrase in options.getDecryptionPassphrases()) {
            for (skesk in esks.skesks) {
                LOGGER.debug("Attempt decryption with provided passphrase")
                val algorithm = SymmetricKeyAlgorithm.requireFromId(skesk.algorithm)
                if (!isAcceptable(algorithm)) {
                    LOGGER.debug(
                        "Skipping SKESK with unacceptable encapsulation algorithm $algorithm")
                    continue
                }

                val decryptorFactory =
                    api.implementation.pbeDataDecryptorFactory(passphrase.getChars())
                if (decryptSKESKAndStream(esks, skesk, decryptorFactory)) {
                    return true
                }
            }
        }

        val postponedDueToMissingPassphrase =
            mutableListOf<Pair<OpenPGPSecretKey, PGPPublicKeyEncryptedData>>()

        // try (known) secret keys
        esks.pkesks.forEach { pkesk ->
            LOGGER.debug("Encountered PKESK for recipient ${pkesk.keyIdentifier}")
            val decryptionKeyCandidates = getDecryptionKeys(pkesk)
            for (decryptionKeys in decryptionKeyCandidates) {
                val secretKey = decryptionKeys.getSecretKeyFor(pkesk)!!
                if (!secretKey.isEncryptionKey &&
                    !options.getAllowDecryptionWithNonEncryptionKey()) {
                    LOGGER.debug(
                        "Message is encrypted for ${secretKey.keyIdentifier}, but the key is not encryption capable.")
                    continue
                }

                LOGGER.debug("Attempt decryption using secret key ${decryptionKeys.keyIdentifier}")
                val protector = options.getSecretKeyProtector(decryptionKeys) ?: continue
                if (!protector.hasPassphraseFor(secretKey.keyIdentifier)) {
                    LOGGER.debug(
                        "Missing passphrase for key ${decryptionKeys.keyIdentifier}. Postponing decryption until all other keys were tried.")
                    postponedDueToMissingPassphrase.add(secretKey to pkesk)
                    continue
                }

                if (hasUnsupportedS2KSpecifier(secretKey)) {
                    continue
                }

                if (secretKey.hasExternalSecretKey()) {
                    LOGGER.debug(
                        "Decryption key ${secretKey.keyIdentifier} is located on an external device, e.g. a smartcard (0x${Hex.toHexString(secretKey.cardSerial)})")
                    for (hardwareTokenBackend in options.hardwareTokenBackends) {
                        LOGGER.debug(
                            "Attempt decryption with ${hardwareTokenBackend.getBackendName()} backend.")
                        if (decryptWithHardwareKey(
                            hardwareTokenBackend,
                            esks,
                            secretKey,
                            protector,
                            SubkeyIdentifier(
                                secretKey.openPGPKey.pgpSecretKeyRing, secretKey.keyIdentifier),
                            pkesk)) {
                            return true
                        }
                    }
                } else {
                    val privateKey =
                        try {
                            unlockSecretKey(secretKey, protector)
                        } catch (e: PGPException) {
                            throw WrongPassphraseException(secretKey.keyIdentifier, e)
                        }
                    if (decryptWithPrivateKey(
                        esks,
                        privateKey.keyPair,
                        SubkeyIdentifier(
                            secretKey.openPGPKey.pgpSecretKeyRing, secretKey.keyIdentifier),
                        pkesk)) {
                        return true
                    }
                }
            }
        }

        // try anonymous secret keys
        for (pkesk in esks.anonPkesks) {
            for (decryptionKey in findPotentialDecryptionKeys(pkesk)) {
                if (hasUnsupportedS2KSpecifier(decryptionKey)) {
                    continue
                }

                LOGGER.debug("Attempt decryption of anonymous PKESK with key $decryptionKey.")
                val protector = options.getSecretKeyProtector(decryptionKey.openPGPKey) ?: continue

                if (!protector.hasPassphraseFor(decryptionKey.keyIdentifier)) {
                    LOGGER.debug(
                        "Missing passphrase for key ${decryptionKey.keyIdentifier}. Postponing decryption until all other keys were tried.")
                    postponedDueToMissingPassphrase.add(decryptionKey to pkesk)
                    continue
                }

                val privateKey = decryptionKey.unlock(protector)
                if (decryptWithPrivateKey(
                    esks, privateKey.keyPair, SubkeyIdentifier(decryptionKey), pkesk)) {
                    return true
                }
            }
        }

        if (options.getMissingKeyPassphraseStrategy() ==
            MissingKeyPassphraseStrategy.THROW_EXCEPTION) {
            // Non-interactive mode: Throw an exception with all locked decryption keys
            postponedDueToMissingPassphrase
                .map { SubkeyIdentifier(it.first) }
                .also { if (it.isNotEmpty()) throw MissingPassphraseException(it.toSet()) }
        } else if (options.getMissingKeyPassphraseStrategy() ==
            MissingKeyPassphraseStrategy.INTERACTIVE) {
            for ((secretKey, pkesk) in postponedDueToMissingPassphrase) {
                val keyId = secretKey.keyIdentifier
                val decryptionKeys = getDecryptionKey(pkesk)!!
                val decryptionKeyId = SubkeyIdentifier(decryptionKeys.pgpSecretKeyRing, keyId)
                if (hasUnsupportedS2KSpecifier(secretKey)) {
                    continue
                }

                LOGGER.debug(
                    "Attempt decryption with key $decryptionKeyId while interactively requesting its passphrase.")
                val protector = options.getSecretKeyProtector(decryptionKeys) ?: continue
                val privateKey: OpenPGPPrivateKey =
                    try {
                        unlockSecretKey(secretKey, protector)
                    } catch (e: PGPException) {
                        throw WrongPassphraseException(secretKey.keyIdentifier, e)
                    }
                if (decryptWithPrivateKey(esks, privateKey.keyPair, decryptionKeyId, pkesk)) {
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

    private fun decryptWithHardwareKey(
        hardwareTokenBackend: HardwareTokenBackend,
        esks: ESKsAndData,
        secretKey: OpenPGPSecretKey,
        protector: SecretKeyRingProtector,
        subkeyIdentifier: SubkeyIdentifier,
        pkesk: PGPPublicKeyEncryptedData
    ): Boolean {
        val decryptors = hardwareTokenBackend.provideDecryptorsFor(secretKey, protector, pkesk)
        while (decryptors.hasNext()) {
            val decryptor = decryptors.next()
            val success = decryptPKESKAndStream(esks, subkeyIdentifier, decryptor, pkesk)
            if (success) {
                return true
            }
        }
        return false
    }

    private fun decryptWithPrivateKey(
        esks: ESKsAndData,
        privateKey: PGPKeyPair,
        decryptionKeyId: SubkeyIdentifier,
        pkesk: PGPPublicKeyEncryptedData
    ): Boolean {
        val decryptorFactory =
            api.implementation.publicKeyDataDecryptorFactory(privateKey.privateKey)
        return decryptPKESKAndStream(esks, decryptionKeyId, decryptorFactory, pkesk)
    }

    private fun hasUnsupportedS2KSpecifier(secretKey: OpenPGPSecretKey): Boolean {
        val s2k = secretKey.pgpSecretKey.s2K
        if (s2k != null) {
            // 101 is GNU_DUMMY_S2K, which we kind of support
            if (s2k.type in 100..110 && s2k.type != 101) {
                LOGGER.debug(
                    "Skipping PKESK because key ${secretKey.keyIdentifier} has unsupported private S2K specifier ${s2k.type}")
                return true
            }
        }
        return false
    }

    private fun decryptSKESKAndStream(
        esks: ESKsAndData,
        skesk: PGPPBEEncryptedData,
        decryptorFactory: PBEDataDecryptorFactory
    ): Boolean {
        try {
            val decrypted = skesk.getDataStream(decryptorFactory)
            val sessionKey = SessionKey(skesk.getSessionKey(decryptorFactory))
            throwIfUnacceptable(sessionKey.algorithm)
            val encryptedData = esks.toEncryptedData(sessionKey, layerMetadata.depth + 1)
            encryptedData.sessionKey = sessionKey
            encryptedData.addRecipients(esks.pkesks.map { it.keyIdentifier })
            LOGGER.debug("Successfully decrypted data with passphrase")
            val integrityProtected = IntegrityProtectedInputStream(decrypted, skesk, options)
            nestedInputStream =
                OpenPgpMessageInputStream(integrityProtected, options, encryptedData, api)
            return true
        } catch (e: UnacceptableAlgorithmException) {
            throw e
        } catch (e: PGPException) {
            LOGGER.debug(
                "Decryption of encrypted data packet using password failed. Password mismatch?", e)
        }
        return false
    }

    private fun decryptPKESKAndStream(
        esks: ESKsAndData,
        decryptionKeyId: SubkeyIdentifier,
        decryptorFactory: PublicKeyDataDecryptorFactory,
        pkesk: PGPPublicKeyEncryptedData
    ): Boolean {
        try {
            val sessionKey = SessionKey(pkesk.getSessionKey(decryptorFactory))
            throwIfUnacceptable(sessionKey.algorithm)

            val pgpSessionKey = PGPSessionKey(sessionKey.algorithm.algorithmId, sessionKey.key)
            val sessionKeyEncData = esks.esks.extractSessionKeyEncryptedData()
            val decrypted =
                sessionKeyEncData.getDataStream(
                    api.implementation.sessionKeyDataDecryptorFactory(pgpSessionKey))

            val encryptedData = esks.toEncryptedData(sessionKey, layerMetadata.depth)
            encryptedData.decryptionKey = decryptionKeyId
            encryptedData.sessionKey = sessionKey
            encryptedData.addRecipients(esks.pkesks.plus(esks.anonPkesks).map { it.keyIdentifier })
            LOGGER.debug("Successfully decrypted data with key $decryptionKeyId")
            val integrityProtected =
                IntegrityProtectedInputStream(decrypted, sessionKeyEncData, options)
            nestedInputStream =
                OpenPgpMessageInputStream(integrityProtected, options, encryptedData, api)
            return true
        } catch (e: UnacceptableAlgorithmException) {
            throw e
        } catch (e: PGPException) {
            LOGGER.debug("Decryption of encrypted data packet using secret key failed.", e)
        }
        return false
    }

    override fun read(): Int {
        if (nestedInputStream == null) {
            if (packetInputStream != null) {
                syntaxVerifier.next(InputSymbol.END_OF_SEQUENCE)
                syntaxVerifier.assertValid()
            }
            return -1
        }

        val r: Int =
            try {
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
            signatures.finish(layerMetadata)
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
            signatures.finish(layerMetadata)
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

    private fun getDecryptionKey(pkesk: PGPPublicKeyEncryptedData): OpenPGPKey? =
        options.getDecryptionKeys().firstOrNull {
            it.pgpSecretKeyRing.getSecretKeyFor(pkesk) != null &&
                api.inspect(it).decryptionSubkeys.any { subkey ->
                    pkesk.keyIdentifier.matchesExplicit(subkey.keyIdentifier)
                }
        }

    private fun getDecryptionKeys(pkesk: PGPPublicKeyEncryptedData): List<OpenPGPKey> =
        options.getDecryptionKeys().filter {
            it.pgpSecretKeyRing.getSecretKeyFor(pkesk) != null &&
                api.inspect(it).decryptionSubkeys.any { subkey ->
                    pkesk.keyIdentifier.matchesExplicit(subkey.keyIdentifier)
                }
        }

    private fun findPotentialDecryptionKeys(
        pkesk: PGPPublicKeyEncryptedData
    ): List<OpenPGPSecretKey> {
        val algorithm = pkesk.algorithm
        val candidates = mutableListOf<OpenPGPSecretKey>()
        options.getDecryptionKeys().forEach {
            val info = api.inspect(it)
            for (key in info.decryptionSubkeys) {
                if (key.pgpPublicKey.algorithm == algorithm &&
                    info.isSecretKeyAvailable(key.keyIdentifier)) {
                    candidates.add(it.getSecretKey(key.keyIdentifier))
                }
            }
        }
        return candidates
    }

    private fun isAcceptable(algorithm: SymmetricKeyAlgorithm): Boolean =
        api.algorithmPolicy.messageDecryptionAlgorithmPolicy.symmetricAlgorithmPolicy.isAcceptable(
            algorithm)

    private fun throwIfUnacceptable(algorithm: SymmetricKeyAlgorithm) {
        if (!isAcceptable(algorithm)) {
            throw UnacceptableAlgorithmException(
                "Symmetric-Key algorithm $algorithm is not acceptable for message decryption.")
        }
    }

    private class ESKsAndData(val esks: PGPEncryptedDataList) {
        fun toEncryptedData(sk: SessionKey, depth: Int): EncryptedData {
            return when (EncryptedDataPacketType.of(esks)!!) {
                EncryptedDataPacketType.SED ->
                    EncryptedData(
                        MessageEncryptionMechanism.legacyEncryptedNonIntegrityProtected(
                            sk.algorithm.algorithmId),
                        depth)
                EncryptedDataPacketType.SEIPDv1 ->
                    EncryptedData(
                        MessageEncryptionMechanism.integrityProtected(sk.algorithm.algorithmId),
                        depth)
                EncryptedDataPacketType.SEIPDv2 -> {
                    val seipd2 = esks.encryptedData as SymmetricEncIntegrityPacket
                    EncryptedData(
                        MessageEncryptionMechanism.aead(
                            seipd2.cipherAlgorithm, seipd2.aeadAlgorithm),
                        depth)
                }
                EncryptedDataPacketType.LIBREPGP_OED -> {
                    val oed = esks.encryptedData as AEADEncDataPacket
                    EncryptedData(MessageEncryptionMechanism.librePgp(oed.algorithm.toInt()), depth)
                }
            }.also { it.sessionKey = sk }
        }

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
                    if (esk.keyIdentifier.isWildcard) {
                        anonPkesks.add(esk)
                    } else {
                        pkesks.add(esk)
                    }
                } else {
                    throw IllegalArgumentException("Unknown ESK class type ${esk.javaClass}")
                }
            }
        }

        val all: List<PGPEncryptedData>
            get() = skesks.plus(pkesks).plus(anonPkesks)
    }

    private class Signatures(val options: ConsumerOptions, val api: PGPainless) : OutputStream() {
        val detachedSignatures = mutableListOf<OpenPGPDocumentSignature>()
        val prependedSignatures = mutableListOf<OpenPGPDocumentSignature>()
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
            val keyId = signature.issuerKeyId
            if (check.issuer != null) {
                detachedSignatures.add(check)
            } else {
                LOGGER.debug(
                    "No suitable certificate for verification of signature by key ${keyId.openPgpKeyId()} found.")
                detachedSignaturesWithMissingCert.add(
                    SignatureVerification.Failure(
                        check, SignatureValidationException("Missing verification key.")))
            }
        }

        fun addPrependedSignature(signature: PGPSignature) {
            val check = initializeSignature(signature)
            val keyId = signature.issuerKeyId
            if (check.issuer != null) {
                prependedSignatures.add(check)
            } else {
                LOGGER.debug(
                    "No suitable certificate for verification of signature by key ${keyId.openPgpKeyId()} found.")
                prependedSignaturesWithMissingCert.add(
                    SignatureVerification.Failure(
                        check, SignatureValidationException("Missing verification key")))
            }
        }

        fun initializeSignature(signature: PGPSignature): OpenPGPDocumentSignature {
            val certificate =
                findCertificate(signature) ?: return OpenPGPDocumentSignature(signature, null)
            val publicKey =
                certificate.getSigningKeyFor(signature)
                    ?: return OpenPGPDocumentSignature(signature, null)
            initialize(signature, publicKey.pgpPublicKey)
            return OpenPGPDocumentSignature(signature, publicKey)
        }

        fun addOnePassSignature(signature: PGPOnePassSignature) {
            val certificate = findCertificate(signature)

            if (certificate != null) {
                val publicKey = certificate.getSigningKeyFor(signature)
                if (publicKey != null) {
                    val ops = OnePassSignatureCheck(signature, certificate)
                    initialize(signature, publicKey.pgpPublicKey)
                    onePassSignatures.add(ops)
                    literalOPS.add(ops)
                }
            }
            if (signature.isContaining) {
                enterNesting()
            }
        }

        fun addCorrespondingOnePassSignature(signature: PGPSignature, layer: Layer) {
            var found = false
            for (check in onePassSignatures.reversed()) {
                if (!KeyIdentifier.matches(
                    signature.keyIdentifiers, check.onePassSignature.keyIdentifier, true)) {
                    continue
                }
                found = true

                if (check.signature != null) {
                    continue
                }
                check.signature = signature

                val documentSignature =
                    OpenPGPDocumentSignature(
                        signature, check.verificationKeys.getSigningKeyFor(signature))
                val verification = SignatureVerification(documentSignature)

                try {
                    signature.assertCreatedInBounds(
                        options.getVerifyNotBefore(), options.getVerifyNotAfter())
                    if (documentSignature.verify(check.onePassSignature) &&
                        documentSignature.isValid(api.implementation.policy())) {
                        layer.addVerifiedOnePassSignature(verification)
                    } else {
                        throw SignatureValidationException("Incorrect OnePassSignature.")
                    }
                } catch (e: MalformedOpenPGPSignatureException) {
                    throw SignatureValidationException("Malformed OnePassSignature.", e)
                } catch (e: SignatureValidationException) {
                    layer.addRejectedOnePassSignature(
                        SignatureVerification.Failure(verification, e))
                } catch (e: PGPSignatureException) {
                    layer.addRejectedOnePassSignature(
                        SignatureVerification.Failure(
                            verification, SignatureValidationException(e.message, e)))
                }
                break
            }

            if (!found) {
                LOGGER.debug(
                    "No suitable certificate for verification of signature by key ${signature.issuerKeyId.openPgpKeyId()} found.")
                inbandSignaturesWithMissingCert.add(
                    SignatureVerification.Failure(
                        OpenPGPDocumentSignature(signature, null),
                        SignatureValidationException("Missing verification key.")))
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

        private fun findCertificate(signature: PGPSignature): OpenPGPCertificate? {
            val cert = options.getCertificateSource().getCertificate(signature)
            if (cert != null) {
                return cert
            }

            if (options.getMissingCertificateCallback() != null) {
                return options
                    .getMissingCertificateCallback()!!
                    .provide(signature.keyIdentifiers.first())
            }
            return null // TODO: Missing cert for sig
        }

        private fun findCertificate(signature: PGPOnePassSignature): OpenPGPCertificate? {
            val cert = options.getCertificateSource().getCertificate(signature.keyIdentifier)
            if (cert != null) {
                return cert
            }

            if (options.getMissingCertificateCallback() != null) {
                return options.getMissingCertificateCallback()!!.provide(signature.keyIdentifier)
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

        fun finish(layer: Layer) {
            for (detached in detachedSignatures) {
                val verification = SignatureVerification(detached)
                try {
                    detached.signature.assertCreatedInBounds(
                        options.getVerifyNotBefore(), options.getVerifyNotAfter())
                    if (!detached.verify()) {
                        throw SignatureValidationException("Incorrect detached signature.")
                    } else if (!detached.isValid(api.implementation.policy())) {
                        throw SignatureValidationException("Detached signature is not valid.")
                    } else {
                        layer.addVerifiedDetachedSignature(verification)
                    }
                } catch (e: MalformedOpenPGPSignatureException) {
                    throw SignatureValidationException("Malformed detached signature.", e)
                } catch (e: SignatureValidationException) {
                    layer.addRejectedDetachedSignature(
                        SignatureVerification.Failure(verification, e))
                }
            }

            for (prepended in prependedSignatures) {
                val verification = SignatureVerification(prepended)
                try {
                    prepended.signature.assertCreatedInBounds(
                        options.getVerifyNotBefore(), options.getVerifyNotAfter())
                    if (prepended.verify() && prepended.isValid(api.implementation.policy())) {
                        layer.addVerifiedPrependedSignature(verification)
                    } else {
                        throw SignatureValidationException("Incorrect prepended signature.")
                    }
                } catch (e: MalformedOpenPGPSignatureException) {
                    throw SignatureValidationException("Malformed prepended signature.", e)
                } catch (e: SignatureValidationException) {
                    LOGGER.debug("Rejected signature by key ${verification.signingKey}", e)
                    layer.addRejectedPrependedSignature(
                        SignatureVerification.Failure(verification, e))
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

        private fun initialize(signature: PGPSignature, publicKey: PGPPublicKey) {
            val verifierProvider = api.implementation.pgpContentVerifierBuilderProvider()
            try {
                signature.init(verifierProvider, publicKey)
            } catch (e: PGPException) {
                throw RuntimeException(e)
            }
        }

        private fun initialize(ops: PGPOnePassSignature, publicKey: PGPPublicKey) {
            val verifierProvider = api.implementation.pgpContentVerifierBuilderProvider()
            try {
                ops.init(verifierProvider, publicKey)
            } catch (e: PGPException) {
                throw RuntimeException(e)
            }
        }
    }

    companion object {
        @JvmStatic
        private val LOGGER = LoggerFactory.getLogger(OpenPgpMessageInputStream::class.java)

        @JvmStatic
        fun create(inputStream: InputStream, options: ConsumerOptions, api: PGPainless) =
            create(inputStream, options, Message(), api)

        @JvmStatic
        internal fun create(
            inputStream: InputStream,
            options: ConsumerOptions,
            metadata: Layer,
            api: PGPainless
        ): OpenPgpMessageInputStream {
            val openPgpIn = OpenPGPAnimalSnifferInputStream(inputStream)
            openPgpIn.reset()

            if (openPgpIn.isNonOpenPgp || options.isForceNonOpenPgpData()) {
                return OpenPgpMessageInputStream(
                    Type.non_openpgp, openPgpIn, options, metadata, api)
            }

            if (openPgpIn.isBinaryOpenPgp) {
                // Simply consume OpenPGP message
                return OpenPgpMessageInputStream(Type.standard, openPgpIn, options, metadata, api)
            }

            return if (openPgpIn.isAsciiArmored) {
                val armorIn = ArmoredInputStreamFactory.get(openPgpIn)
                if (armorIn.isClearText) {
                    (metadata as Message).setCleartextSigned()
                    OpenPgpMessageInputStream(
                        Type.cleartext_signed, armorIn, options, metadata, api)
                } else {
                    // Simply consume dearmored OpenPGP message
                    OpenPgpMessageInputStream(Type.standard, armorIn, options, metadata, api)
                }
            } else {
                throw AssertionError("Cannot deduce type of data.")
            }
        }
    }
}
