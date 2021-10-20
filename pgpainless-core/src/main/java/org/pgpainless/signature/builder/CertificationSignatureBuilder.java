package org.pgpainless.signature.builder;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.protection.SecretKeyRingProtector;

public class CertificationSignatureBuilder extends AbstractSignatureBuilder<CertificationSignatureBuilder> {

    public CertificationSignatureBuilder(PGPSecretKey certificationKey, SecretKeyRingProtector protector) throws WrongPassphraseException {
        super(SignatureType.GENERIC_CERTIFICATION, certificationKey, protector);
    }

    public PGPSignature build(PGPPublicKey certifiedKey, String userId) throws PGPException {
        return buildAndInitSignatureGenerator().generateCertification(userId, certifiedKey);
    }

    public PGPSignature build(PGPPublicKey certifiedKey, PGPUserAttributeSubpacketVector userAttribute) throws PGPException {
        return buildAndInitSignatureGenerator().generateCertification(userAttribute, certifiedKey);
    }

    @Override
    protected boolean isValidSignatureType(SignatureType type) {
        switch (signatureType) {
            case GENERIC_CERTIFICATION:
            case NO_CERTIFICATION:
            case CASUAL_CERTIFICATION:
            case POSITIVE_CERTIFICATION:
                return true;
            default:
                return false;
        }
    }
}
