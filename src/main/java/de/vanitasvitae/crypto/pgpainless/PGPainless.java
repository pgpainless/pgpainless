package de.vanitasvitae.crypto.pgpainless;

import de.vanitasvitae.crypto.pgpainless.key.generation.KeyRingBuilder;

public class PGPainless {

    public static KeyRingBuilder generateKeyRing() {
        return new KeyRingBuilder();
    }
}
