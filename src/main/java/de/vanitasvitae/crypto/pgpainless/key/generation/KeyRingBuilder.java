package de.vanitasvitae.crypto.pgpainless.key.generation;


import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import de.vanitasvitae.crypto.pgpainless.algorithm.KeyFlag;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.ECDH;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.ECDSA;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.KeyType;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.RSA_GENERAL;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.curve.EllipticCurve;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.length.RsaLength;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
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
    private String userId;
    private char[] passphrase;

    public PGPSecretKeyRing simpleRsaKeyRing(String userId, RsaLength length)
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return withMasterKey(
                        KeySpec.getBuilder()
                                .ofType(RSA_GENERAL.withLength(length))
                                .withDefaultKeyFlags()
                                .withDefaultAlgorithms())
                .withPrimaryUserId(userId)
                .withoutPassphrase()
                .build();
    }

    public PGPSecretKeyRing simpleEcKeyRing(String userId)
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return withSubKey(
                        KeySpec.getBuilder()
                                .ofType(ECDH.fromCurve(EllipticCurve._P256))
                                .withKeyFlags(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS)
                                .withDefaultAlgorithms())
                .withMasterKey(
                        KeySpec.getBuilder()
                                .ofType(ECDSA.fromCurve(EllipticCurve._P256))
                                .withKeyFlags(KeyFlag.AUTHENTICATION, KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                                .withDefaultAlgorithms())
                .withPrimaryUserId(userId)
                .withoutPassphrase()
                .build();
    }

    @Override
    public KeyRingBuilderInterface withSubKey(KeySpec type) {
        KeyRingBuilder.this.keySpecs.add(type);
        return this;
    }

    @Override
    public WithPrimaryUserId withMasterKey(KeySpec spec) {
        if ((spec.getSubpackets().getKeyFlags() & KeyFlags.CERTIFY_OTHER) == 0) {
            throw new IllegalArgumentException("Certification Key MUST have KeyFlag CERTIFY_OTHER");
        }
        KeyRingBuilder.this.keySpecs.add(0, spec);
        return new WithPrimaryUserIdImpl();
    }

    class WithPrimaryUserIdImpl implements WithPrimaryUserId {

        @Override
        public WithPassphrase withPrimaryUserId(String userId) {
            KeyRingBuilder.this.userId = userId;
            return new WithPassphraseImpl();
        }

        @Override
        public WithPassphrase withPrimaryUserId(byte[] userId) {
            return withPrimaryUserId(new String(userId, UTF8));
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
            public PGPSecretKeyRing build() throws NoSuchAlgorithmException, PGPException, NoSuchProviderException,
                    InvalidAlgorithmParameterException {

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
                // Remove master key, so that we later only add sub keys.
                keySpecs.remove(0);

                // Generate Master Key
                PGPKeyPair certKey = generateKeyPair(certKeySpec);

                // Signer for creating self-signature
                PGPContentSignerBuilder signer = new JcaPGPContentSignerBuilder(
                        certKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA512)
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME);

                PGPSignatureSubpacketVector hashedSubPackets = certKeySpec.getSubpackets();

                // Generator which the user can get the key pair from
                PGPKeyRingGenerator ringGenerator = new PGPKeyRingGenerator(
                        PGPSignature.POSITIVE_CERTIFICATION, certKey,
                        userId, calculator,
                        hashedSubPackets, null, signer, encryptor);

                for (KeySpec subKeySpec : keySpecs) {
                    PGPKeyPair subKey = generateKeyPair(subKeySpec);
                    if (subKeySpec.isInheritedSubPackets()) {
                        ringGenerator.addSubKey(subKey);
                    } else {
                        ringGenerator.addSubKey(subKey, subKeySpec.getSubpackets(), null);
                    }
                }

                return ringGenerator.generateSecretKeyRing();
            }

            private PGPKeyPair generateKeyPair(KeySpec spec)
                    throws NoSuchProviderException, NoSuchAlgorithmException, PGPException,
                    InvalidAlgorithmParameterException {
                KeyType type = spec.getKeyType();
                KeyPairGenerator certKeyGenerator = KeyPairGenerator.getInstance(
                        type.getName(), BouncyCastleProvider.PROVIDER_NAME);
                certKeyGenerator.initialize(type.getAlgorithmSpec());

                // Create raw Key Pair
                KeyPair keyPair = certKeyGenerator.generateKeyPair();

                // Form PGP key pair
                PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(type.getAlgorithm().getAlgorithmId(),
                        keyPair, new Date());

                return pgpKeyPair;
            }
        }
    }
}