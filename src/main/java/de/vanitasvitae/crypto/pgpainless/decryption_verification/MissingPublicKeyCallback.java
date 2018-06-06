package de.vanitasvitae.crypto.pgpainless.decryption_verification;

public interface MissingPublicKeyCallback {

    void onMissingPublicKeyEncountered(Long keyId);

}
