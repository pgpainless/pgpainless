/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.encryption_signing;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.DetachedSignature;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.util.ArmoredOutputStreamFactory;
import org.pgpainless.util.Passphrase;

/**
 * This class is based upon Jens Neuhalfen's Bouncy-GPG PGPEncryptingStream.
 * @see <a href="https://github.com/neuhalje/bouncy-gpg/blob/master/src/main/java/name/neuhalfen/projects/crypto/bouncycastle/openpgp/encrypting/PGPEncryptingStream.java">Source</a>
 */
public final class EncryptionStream extends OutputStream {

    public enum Purpose {
        /**
         * The stream will encrypt communication that goes over the wire.
         * Eg. EMail, Chat...
         */
        COMMUNICATIONS,
        /**
         * The stream will encrypt data that is stored on disk.
         * Eg. Encrypted backup...
         */
        STORAGE,
        /**
         * The stream will use keys with either flags to encrypt the data.
         */
        STORAGE_AND_COMMUNICATIONS
    }

    private static final Logger LOGGER = Logger.getLogger(EncryptionStream.class.getName());
    private static final Level LEVEL = Level.FINE;

    private static final int BUFFER_SIZE = 1 << 8;

    private final SymmetricKeyAlgorithm symmetricKeyAlgorithm;
    private final HashAlgorithm hashAlgorithm;
    private final CompressionAlgorithm compressionAlgorithm;
    private final Set<PGPPublicKey> encryptionKeys;
    private final Set<Passphrase> encryptionPassphrases;
    private final boolean detachedSignature;
    private final SignatureType signatureType;
    private final Map<OpenPgpV4Fingerprint, PGPPrivateKey> signingKeys;
    private final boolean asciiArmor;

    private final OpenPgpMetadata.Builder resultBuilder = OpenPgpMetadata.getBuilder();

    private Map<OpenPgpV4Fingerprint, PGPSignatureGenerator> signatureGenerators = new ConcurrentHashMap<>();
    private boolean closed = false;

    OutputStream outermostStream = null;

    private ArmoredOutputStream armorOutputStream = null;
    private OutputStream publicKeyEncryptedStream = null;

    private PGPCompressedDataGenerator compressedDataGenerator;
    private BCPGOutputStream basicCompressionStream;

    private PGPLiteralDataGenerator literalDataGenerator;
    private OutputStream literalDataStream;

    EncryptionStream(@Nonnull OutputStream targetOutputStream,
                     @Nonnull Set<PGPPublicKey> encryptionKeys,
                     @Nonnull Set<Passphrase> encryptionPassphrases,
                     boolean detachedSignature,
                     SignatureType signatureType,
                     @Nonnull Map<OpenPgpV4Fingerprint, PGPPrivateKey> signingKeys,
                     @Nonnull SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                     @Nonnull HashAlgorithm hashAlgorithm,
                     @Nonnull CompressionAlgorithm compressionAlgorithm,
                     boolean asciiArmor,
                     @Nonnull String fileName,
                     boolean forYourEyesOnly)
            throws IOException, PGPException {

        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.compressionAlgorithm = compressionAlgorithm;
        this.encryptionKeys = Collections.unmodifiableSet(encryptionKeys);
        this.encryptionPassphrases = Collections.unmodifiableSet(encryptionPassphrases);
        this.detachedSignature = detachedSignature;
        this.signatureType = signatureType;
        this.signingKeys = Collections.unmodifiableMap(signingKeys);
        this.asciiArmor = asciiArmor;

        outermostStream = targetOutputStream;
        prepareArmor();
        prepareEncryption();
        prepareSigning();
        prepareCompression();
        prepareOnePassSignatures();
        prepareLiteralDataProcessing(fileName, forYourEyesOnly);
        prepareResultBuilder();
    }

    private void prepareArmor() {
        if (!asciiArmor) {
            LOGGER.log(LEVEL, "Encryption output will be binary");
            return;
        }

        LOGGER.log(LEVEL, "Wrap encryption output in ASCII armor");
        armorOutputStream = ArmoredOutputStreamFactory.get(outermostStream);
        outermostStream = armorOutputStream;
    }

    private void prepareEncryption() throws IOException, PGPException {
        if (encryptionKeys.isEmpty() && encryptionPassphrases.isEmpty()) {
            return;
        }

        LOGGER.log(LEVEL, "At least one encryption key is available -> encrypt using " + symmetricKeyAlgorithm);
        PGPDataEncryptorBuilder dataEncryptorBuilder =
                ImplementationFactory.getInstance().getPGPDataEncryptorBuilder(symmetricKeyAlgorithm);

        // Simplify once https://github.com/bcgit/bc-java/pull/859 is merged
        if (dataEncryptorBuilder instanceof BcPGPDataEncryptorBuilder) {
            ((BcPGPDataEncryptorBuilder) dataEncryptorBuilder).setWithIntegrityPacket(true);
        } else if (dataEncryptorBuilder instanceof JcePGPDataEncryptorBuilder) {
            ((JcePGPDataEncryptorBuilder) dataEncryptorBuilder).setWithIntegrityPacket(true);
        }

        PGPEncryptedDataGenerator encryptedDataGenerator =
                new PGPEncryptedDataGenerator(dataEncryptorBuilder);

        for (PGPPublicKey key : encryptionKeys) {
            LOGGER.log(LEVEL, "Encrypt for key " + Long.toHexString(key.getKeyID()));
            PublicKeyKeyEncryptionMethodGenerator keyEncryption =
                    ImplementationFactory.getInstance().getPublicKeyKeyEncryptionMethodGenerator(key);
            encryptedDataGenerator.addMethod(keyEncryption);
        }

        for (Passphrase passphrase : encryptionPassphrases) {
            PBEKeyEncryptionMethodGenerator passphraseEncryption =
                    ImplementationFactory.getInstance().getPBEKeyEncryptionMethodGenerator(passphrase);
            encryptedDataGenerator.addMethod(passphraseEncryption);
        }

        publicKeyEncryptedStream = encryptedDataGenerator.open(outermostStream, new byte[BUFFER_SIZE]);
        outermostStream = publicKeyEncryptedStream;
    }

    private void prepareSigning() throws PGPException {
        if (signingKeys.isEmpty()) {
            return;
        }

        LOGGER.log(LEVEL, "At least one signing key is available -> sign " + hashAlgorithm + " hash of message");
        for (OpenPgpV4Fingerprint fingerprint : signingKeys.keySet()) {
            PGPPrivateKey privateKey = signingKeys.get(fingerprint);
            LOGGER.log(LEVEL, "Sign using key " + fingerprint);
            PGPContentSignerBuilder contentSignerBuilder = ImplementationFactory.getInstance()
                    .getPGPContentSignerBuilder(
                            privateKey.getPublicKeyPacket().getAlgorithm(),
                            hashAlgorithm.getAlgorithmId());

            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
            signatureGenerator.init(signatureType.getCode(), privateKey);
            signatureGenerators.put(fingerprint, signatureGenerator);
        }
    }

    private void prepareCompression() throws IOException {
        compressedDataGenerator = new PGPCompressedDataGenerator(
            compressionAlgorithm.getAlgorithmId());
        if (compressionAlgorithm == CompressionAlgorithm.UNCOMPRESSED) {
            return;
        }

        LOGGER.log(LEVEL, "Compress using " + compressionAlgorithm);
        basicCompressionStream = new BCPGOutputStream(compressedDataGenerator.open(outermostStream));
        outermostStream = basicCompressionStream;
    }

    private void prepareOnePassSignatures() throws IOException, PGPException {
        for (PGPSignatureGenerator signatureGenerator : signatureGenerators.values()) {
            signatureGenerator.generateOnePassVersion(false).encode(outermostStream);
        }
    }

    private void prepareLiteralDataProcessing(@Nonnull String fileName, boolean forYourEyesOnly) throws IOException {
        literalDataGenerator = new PGPLiteralDataGenerator();
        String name = fileName;
        if (forYourEyesOnly) {
            name = PGPLiteralData.CONSOLE;
        }
        literalDataStream = literalDataGenerator.open(outermostStream,
                PGPLiteralData.BINARY, name, new Date(), new byte[BUFFER_SIZE]);
        outermostStream = literalDataStream;
    }

    private void prepareResultBuilder() {
        for (PGPPublicKey recipient : encryptionKeys) {
            resultBuilder.addRecipientKeyId(recipient.getKeyID());
        }
        resultBuilder.setSymmetricKeyAlgorithm(symmetricKeyAlgorithm);
        resultBuilder.setCompressionAlgorithm(compressionAlgorithm);
    }

    @Override
    public void write(int data) throws IOException {
        outermostStream.write(data);

        for (PGPSignatureGenerator signatureGenerator : signatureGenerators.values()) {
            byte asByte = (byte) (data & 0xff);
            signatureGenerator.update(asByte);
        }
    }

    @Override
    public void write(byte[] buffer) throws IOException {
        write(buffer, 0, buffer.length);
    }


    @Override
    public void write(byte[] buffer, int off, int len) throws IOException {
        outermostStream.write(buffer, 0, len);
        for (PGPSignatureGenerator signatureGenerator : signatureGenerators.values()) {
            signatureGenerator.update(buffer, 0, len);
        }
    }

    @Override
    public void flush() throws IOException {
        outermostStream.flush();
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }

        // Literal Data
        literalDataStream.flush();
        literalDataStream.close();
        literalDataGenerator.close();

        writeSignatures();

        // Compressed Data
        compressedDataGenerator.close();

        // Public Key Encryption
        if (publicKeyEncryptedStream != null) {
            publicKeyEncryptedStream.flush();
            publicKeyEncryptedStream.close();
        }

        // Armor
        if (armorOutputStream != null) {
            armorOutputStream.flush();
            armorOutputStream.close();
        }
        closed = true;
    }

    private void writeSignatures() throws IOException {
        for (OpenPgpV4Fingerprint fingerprint : signatureGenerators.keySet()) {
            PGPSignatureGenerator signatureGenerator = signatureGenerators.get(fingerprint);
            try {
                PGPSignature signature = signatureGenerator.generate();
                if (!detachedSignature) {
                    signature.encode(outermostStream);
                }
                resultBuilder.addDetachedSignature(new DetachedSignature(signature, fingerprint));
            } catch (PGPException e) {
                throw new IOException(e);
            }
        }
    }

    public OpenPgpMetadata getResult() {
        if (!closed) {
            throw new IllegalStateException("EncryptionStream must be closed before accessing the Result.");
        }
        return resultBuilder.build();
    }
}
