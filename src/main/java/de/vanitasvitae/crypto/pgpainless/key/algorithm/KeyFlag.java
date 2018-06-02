package de.vanitasvitae.crypto.pgpainless.key.algorithm;

import org.bouncycastle.bcpg.sig.KeyFlags;

public enum KeyFlag {

    CERTIFY_OTHER(  KeyFlags.CERTIFY_OTHER),
    SIGN_DATA(      KeyFlags.SIGN_DATA),
    ENCRYPT_COMMS(  KeyFlags.ENCRYPT_COMMS),
    ENCRYPT_STORAGE(KeyFlags.ENCRYPT_STORAGE),
    SPLIT(          KeyFlags.SPLIT),
    AUTHENTICATION( KeyFlags.AUTHENTICATION),
    SHARED(         KeyFlags.SHARED),
    ;

    private final int flag;

    KeyFlag(int flag) {
        this.flag = flag;
    }

    public int getFlag() {
        return flag;
    }
}
