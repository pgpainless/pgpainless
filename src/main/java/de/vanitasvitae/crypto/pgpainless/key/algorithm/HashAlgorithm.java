package de.vanitasvitae.crypto.pgpainless.key.algorithm;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.bcpg.HashAlgorithmTags;

public enum HashAlgorithm {

    MD5(        HashAlgorithmTags.MD5),
    SHA1(       HashAlgorithmTags.SHA1),
    RIPEMD160(  HashAlgorithmTags.RIPEMD160),
    DOUBLE_SHA( HashAlgorithmTags.DOUBLE_SHA),
    MD2(        HashAlgorithmTags.MD2),
    TIGER_192(  HashAlgorithmTags.TIGER_192),
    HAVAL_5_160(HashAlgorithmTags.HAVAL_5_160),
    SHA256(     HashAlgorithmTags.SHA256),
    SHA384(     HashAlgorithmTags.SHA384),
    SHA512(     HashAlgorithmTags.SHA512),
    SHA224(     HashAlgorithmTags.SHA224),
    ;
    //                                                         Coincidence? I don't this so...
    private static final Map<Integer, HashAlgorithm> MAP = new HashMap<>();

    static {
        for (HashAlgorithm h : HashAlgorithm.values()) {
            MAP.put(h.algorithmId, h);
        }
    }

    public static HashAlgorithm fromId(int id) {
        return MAP.get(id);
    }

    private final int algorithmId;

    HashAlgorithm(int id) {
        this.algorithmId = id;
    }

    public int getAlgorithmId() {
        return algorithmId;
    }
}
