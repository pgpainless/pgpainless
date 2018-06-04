package de.vanitasvitae.crypto.pgpainless.algorithm;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;

public enum PublicKeyAlgorithm {

    RSA_GENERAL(    PublicKeyAlgorithmTags.RSA_GENERAL),
    RSA_ENCRYPT(    PublicKeyAlgorithmTags.RSA_ENCRYPT),
    RSA_SIGN(       PublicKeyAlgorithmTags.RSA_SIGN),
    ELGAMAL_ENCRYPT(PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT),
    DSA(PublicKeyAlgorithmTags.DSA),
    /**
     * @deprecated use {@link #ECDH} instead.
     */
    EC(             PublicKeyAlgorithmTags.EC),
    ECDH(           PublicKeyAlgorithmTags.ECDH),
    ECDSA(          PublicKeyAlgorithmTags.ECDSA),
    ELGAMAL_GENERAL(PublicKeyAlgorithmTags.ELGAMAL_GENERAL),
    DIFFIE_HELLMAN( PublicKeyAlgorithmTags.DIFFIE_HELLMAN),
    ;

    private static final Map<Integer, PublicKeyAlgorithm> MAP = new HashMap<>();

    static {
        for (PublicKeyAlgorithm p : PublicKeyAlgorithm.values()) {
            MAP.put(p.algorithmId, p);
        }
    }

    public static PublicKeyAlgorithm fromId(int id) {
        return MAP.get(id);
    }

    private final int algorithmId;

    PublicKeyAlgorithm(int algorithmId) {
        this.algorithmId = algorithmId;
    }

    public int getAlgorithmId() {
        return algorithmId;
    }
}
