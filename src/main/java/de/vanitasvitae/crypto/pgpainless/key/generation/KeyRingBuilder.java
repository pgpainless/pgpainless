package de.vanitasvitae.crypto.pgpainless.key.generation;


import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import de.vanitasvitae.crypto.pgpainless.key.algorithm.KeyFlag;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.KeyType;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

public class KeyRingBuilder implements KeyRingBuilderInterface {

    private final Charset UTF8 = Charset.forName("UTF-8");

    private List<KeySpec> keySpecs = new ArrayList<>();
    private List<String> userIds = new ArrayList<>();
    private char[] passphrase;

    @Override
    public WithSubKeyType generateCompositeKeyRing() {
        return new WithSubKeyTypeImpl();
    }

    @Override
    public WithCertificationKeyType generateSingleKeyKeyRing() {
        return new WithCertificationKeyTypeImpl();
    }

    class WithSubKeyTypeImpl implements WithSubKeyType {

        @Override
        public WithSubKeyType withSubKey(KeySpec type) {
            KeyRingBuilder.this.keySpecs.add(type);
            return this;
        }

        @Override
        public WithCertificationKeyType done() {
            return new WithCertificationKeyTypeImpl();
        }
    }

    class WithCertificationKeyTypeImpl implements WithCertificationKeyType {

        @Override
        public WithPrimaryUserId withCertificationKeyType(KeySpec spec) {
            if ((spec.getKeyFlags() & KeyFlag.CERTIFY_OTHER.getFlag()) == 0) {
                throw new IllegalArgumentException("Certification Key MUST have KeyFlag CERTIFY_OTHER");
            }
            KeyRingBuilder.this.keySpecs.add(spec);
            return new WithPrimaryUserIdImpl();
        }
    }

    class WithPrimaryUserIdImpl implements WithPrimaryUserId {

        @Override
        public WithAdditionalUserIds withPrimaryUserId(String userId) {
            KeyRingBuilder.this.userIds.add(userId);
            return new WithAdditionalUserIdsImpl();
        }

        @Override
        public WithAdditionalUserIds withPrimaryUserId(byte[] userId) {
            return withPrimaryUserId(new String(userId, UTF8));
        }
    }

    class WithAdditionalUserIdsImpl implements WithAdditionalUserIds {

        @Deprecated
        @Override
        public WithAdditionalUserIds withAdditionalUserId(String userId) {
            KeyRingBuilder.this.userIds.add(userId);
            return this;
        }

        @Deprecated
        @Override
        public WithAdditionalUserIds withAdditionalUserId(byte[] userId) {
            return withAdditionalUserId(new String(userId, UTF8));
        }

        @Override
        public WithPassphrase done() {
            return new WithPassphraseImpl();
        }
    }

    class WithPassphraseImpl implements WithPassphrase {

        @Override
        public Build withPassphrase(String passphrase) {
            return withPassphrase(passphrase.toCharArray());
        }

        @Override
        public Build withPassphrase(char[] passphrase) {
            KeyRingBuilder.this.passphrase = passphrase;
            return new BuildImpl();
        }

        @Override
        public Build withoutPassphrase() {
            KeyRingBuilder.this.passphrase = null;
            return new BuildImpl();
        }

        class BuildImpl implements Build {

            @Override
            public PGPSecretKeyRing build() throws NoSuchAlgorithmException, PGPException, NoSuchProviderException {

                // Hash Calculator
                PGPDigestCalculator calculator = new JcaPGPDigestCalculatorProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build()
                        .get(HashAlgorithmTags.SHA1);

                // Encryptor for encrypting secret keys
                PBESecretKeyEncryptor encryptor = passphrase == null ?
                        null : // unencrypted key pair, otherwise AES-256 encrypted
                        new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, calculator)
                                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                .build(passphrase);

                // First key is the Master Key
                KeySpec certKeySpec = keySpecs.get(0);
                KeyType certKeyType = certKeySpec.getKeyType();
                keySpecs.remove(0); // Remove master key, so that we later only add sub keys.

                // Generate Master Key
                PGPKeyPair certKey = generateKeyPair(certKeySpec);

                // Signer for creating self-signature
                PGPContentSignerBuilder signer = new JcaPGPContentSignerBuilder(
                        certKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256);

                // Mimic GnuPGs signature sub packets
                PGPSignatureSubpacketGenerator hashedSubPackets = new PGPSignatureSubpacketGenerator();

                // Key flags
                hashedSubPackets.setKeyFlags(true, certKeySpec.getKeyFlags());

                // Encryption Algorithms
                hashedSubPackets.setPreferredSymmetricAlgorithms(true,
                        certKeySpec.getPreferredAlgorithms().getSymmetricKeyAlgorithmIds());

                // Hash Algorithms
                hashedSubPackets.setPreferredHashAlgorithms(true,
                        certKeySpec.getPreferredAlgorithms().getHashAlgorithmIds());

                // Compression Algorithms
                hashedSubPackets.setPreferredCompressionAlgorithms(true,
                        certKeySpec.getPreferredAlgorithms().getCompressionAlgorithmIds());

                // Modification Detection
                hashedSubPackets.setFeature(true, certKeySpec.getFeatures());

                // Generator which the user can get the key pair from
                PGPKeyRingGenerator ringGenerator = new PGPKeyRingGenerator(
                        PGPSignature.POSITIVE_CERTIFICATION, certKey,
                        userIds.get(0), calculator,
                        hashedSubPackets.generate(), null, signer, encryptor);

                for (KeySpec subKeySpec : keySpecs) {
                    PGPKeyPair subKey = generateKeyPair(subKeySpec);
                    ringGenerator.addSubKey(subKey);
                }

                return ringGenerator.generateSecretKeyRing();
            }

            private PGPKeyPair generateKeyPair(KeySpec spec)
                    throws NoSuchProviderException, NoSuchAlgorithmException, PGPException {
                KeyType type = spec.getKeyType();
                KeyPairGenerator certKeyGenerator = KeyPairGenerator.getInstance(
                        type.getName(), BouncyCastleProvider.PROVIDER_NAME);
                certKeyGenerator.initialize(type.getLength());

                // Create raw Key Pair
                KeyPair rawKeyPair = certKeyGenerator.generateKeyPair();

                // Form PGP key pair
                PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(type.getAlgorithm().getAlgorithmId(),
                        rawKeyPair, new Date());

                return pgpKeyPair;
            }
        }
    }
}