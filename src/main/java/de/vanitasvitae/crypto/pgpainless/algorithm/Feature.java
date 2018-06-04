package de.vanitasvitae.crypto.pgpainless.algorithm;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.bcpg.sig.Features;

public enum Feature {
    MODIFICATION_DETECTION(Features.FEATURE_MODIFICATION_DETECTION),
    ;

    private static final Map<Byte, Feature> MAP = new HashMap<>();

    static {
        for (Feature f : Feature.values()) {
            MAP.put(f.featureId, f);
        }
    }

    public static Feature fromId(byte id) {
        return MAP.get(id);
    }

    private final byte featureId;

    Feature(byte featureId) {
        this.featureId = featureId;
    }

    public byte getFeatureId() {
        return featureId;
    }
}
