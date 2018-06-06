package de.vanitasvitae.crypto.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.PainlessResult;
import de.vanitasvitae.crypto.pgpainless.PainlessStream;
import de.vanitasvitae.crypto.pgpainless.algorithm.CompressionAlgorithm;
import de.vanitasvitae.crypto.pgpainless.algorithm.SymmetricKeyAlgorithm;
import de.vanitasvitae.crypto.pgpainless.encryption_signing.SecretKeyRingDecryptor;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

public class InputStreamFactory {

    private InputStream inputStream;

    private final PGPSecretKeyRingCollection decryptionKeys;
    private final SecretKeyRingDecryptor decryptionKeyDecryptor;
    private final Set<PGPPublicKeyRing> verificationKeys = new HashSet<>();
    private final Set<Long> trustedKeyIds = new HashSet<>();
    private final MissingPublicKeyCallback missingPublicKeyCallback;

    private final PainlessResult.Builder resultBuilder = PainlessResult.getBuilder();
    private final PGPContentVerifierBuilderProvider verifierBuilderProvider = new BcPGPContentVerifierBuilderProvider();
    private final Map<Long, PGPOnePassSignature> verifiableOnePassSignatures = new HashMap<>();

    private InputStreamFactory(PGPSecretKeyRingCollection decryptionKeys,
                               SecretKeyRingDecryptor decryptor,
                               Set<PGPPublicKeyRing> verificationKeys,
                               Set<Long> trustedKeyIds,
                               MissingPublicKeyCallback missingPublicKeyCallback)
            throws IOException {
        this.decryptionKeys = decryptionKeys;
        this.decryptionKeyDecryptor = decryptor;
        this.verificationKeys.addAll(verificationKeys != null ? verificationKeys : Collections.emptyList());
        this.trustedKeyIds.addAll(trustedKeyIds != null ? trustedKeyIds : Collections.emptyList());
        this.missingPublicKeyCallback = missingPublicKeyCallback;
    }

    public static PainlessResult.ResultAndInputStream create(InputStream inputStream,
                                                             PGPSecretKeyRingCollection decryptionKeys,
                                                             SecretKeyRingDecryptor decryptor,
                                                             Set<PGPPublicKeyRing> verificationKeys,
                                                             Set<Long> trustedKeyIds,
                                                             MissingPublicKeyCallback missingPublicKeyCallback)
            throws IOException, PGPException {

        InputStreamFactory factory =  new InputStreamFactory(decryptionKeys,
                decryptor,
                verificationKeys,
                trustedKeyIds,
                missingPublicKeyCallback);

        PGPObjectFactory objectFactory = new PGPObjectFactory(
                PGPUtil.getDecoderStream(inputStream), new BcKeyFingerprintCalculator());

        return new PainlessResult.ResultAndInputStream(
                factory.resultBuilder,
                new PainlessStream.In(factory.wrap(objectFactory)));
    }

    private InputStream wrap(PGPObjectFactory objectFactory) throws IOException, PGPException {
        KeyFingerPrintCalculator fingerCalc = new BcKeyFingerprintCalculator();

        Object pgpObj = null;
        while ((pgpObj = objectFactory.nextObject()) != null) {

            if (pgpObj instanceof PGPEncryptedDataList) {
                PGPEncryptedDataList encDataList = (PGPEncryptedDataList) pgpObj;
                InputStream nextStream = decrypt(encDataList);
                objectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(nextStream), fingerCalc);
                return wrap(objectFactory);
            }

            if (pgpObj instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData) pgpObj;
                InputStream nextStream = compressedData.getDataStream();
                resultBuilder.setCompressionAlgorithm(CompressionAlgorithm.fromId(compressedData.getAlgorithm()));
                objectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(nextStream), fingerCalc);
                return wrap(objectFactory);
            }

            if (pgpObj instanceof PGPOnePassSignatureList) {
                PGPOnePassSignatureList onePassSignatures = (PGPOnePassSignatureList) pgpObj;
                verify(onePassSignatures);
            }

            if (pgpObj instanceof PGPLiteralData) {
                PGPLiteralData literalData = (PGPLiteralData) pgpObj;
                InputStream literalDataInputStream = literalData.getInputStream();

                if (verifiableOnePassSignatures.isEmpty()) {
                    return literalDataInputStream;
                }

                return new SignatureVerifyingInputStream(literalDataInputStream,
                        objectFactory, verifiableOnePassSignatures, resultBuilder);
            }
        }

        throw new PGPException("No Literal Data Packet found!");
    }

    private InputStream decrypt(PGPEncryptedDataList encryptedDataList)
            throws PGPException {
        Iterator<?> iterator = encryptedDataList.getEncryptedDataObjects();
        if (!iterator.hasNext()) {
            throw new PGPException("Decryption failed - No encrypted data found!");
        }

        PGPPrivateKey decryptionKey = null;
        PGPPublicKeyEncryptedData encryptedSessionKey = null;
        while (iterator.hasNext()) {
            encryptedSessionKey = (PGPPublicKeyEncryptedData) iterator.next();
            long keyId = encryptedSessionKey.getKeyID();

            resultBuilder.addRecipientKeyId(keyId);

            if (decryptionKey != null) {
                continue;
            }

            PGPSecretKey secretKey = decryptionKeys.getSecretKey(keyId);
            if (secretKey != null) {
                decryptionKey = secretKey.extractPrivateKey(decryptionKeyDecryptor.getDecryptor(keyId));
                resultBuilder.setDecryptionKeyId(keyId);
            }
        }

        if (decryptionKey == null) {
            throw new PGPException("Decryption failed - No suitable decryption key found!");
        }

        PublicKeyDataDecryptorFactory keyDecryptor = new BcPublicKeyDataDecryptorFactory(decryptionKey);
        resultBuilder.setSymmetricKeyAlgorithm(
                SymmetricKeyAlgorithm.forId(encryptedSessionKey.getSymmetricAlgorithm(keyDecryptor)));
        resultBuilder.setIntegrityProtected(encryptedSessionKey.isIntegrityProtected());

        InputStream decryptionStream = encryptedSessionKey.getDataStream(keyDecryptor);

        return decryptionStream;
    }

    private void verify(PGPOnePassSignatureList onePassSignatureList) throws PGPException {
        Iterator<PGPOnePassSignature> iterator = onePassSignatureList.iterator();
        if (!iterator.hasNext()) {
            throw new PGPException("Verification failed - No OnePassSignatures found!");
        }

        while (iterator.hasNext()) {
            PGPOnePassSignature signature = iterator.next();
            long keyId = signature.getKeyID();
            resultBuilder.addSignatureKeyId(keyId);

            // Find public key
            PGPPublicKey verificationKey = null;
            for (PGPPublicKeyRing publicKeyRing : verificationKeys) {
                verificationKey = publicKeyRing.getPublicKey(signature.getKeyID());
            }

            if (verificationKey != null) {
                signature.init(verifierBuilderProvider, verificationKey);
                verifiableOnePassSignatures.put(signature.getKeyID(), signature);
            }
        }
    }
}
