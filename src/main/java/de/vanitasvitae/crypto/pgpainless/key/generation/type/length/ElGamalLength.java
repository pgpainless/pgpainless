package de.vanitasvitae.crypto.pgpainless.key.generation.type.length;

public enum ElGamalLength implements KeyLength {

    _1024(1024),
    _2048(2048),
    _3072(3072),
    ;

    private final int length;

    ElGamalLength(int length) {
        this.length = length;
    }

    @Override
    public int getLength() {
        return length;
    }

}
