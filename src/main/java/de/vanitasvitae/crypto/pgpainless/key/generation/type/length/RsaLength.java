package de.vanitasvitae.crypto.pgpainless.key.generation.type.length;

public enum RsaLength implements KeyLength {
    @Deprecated
    _1024(1024),
    @Deprecated
    _2048(2048),
    _3072(3072),
    _4096(4096),
    _8192(8192),
    ;

    private final int length;

    RsaLength(int length) {
        this.length = length;
    }

    @Override
    public int getLength() {
        return length;
    }
}
