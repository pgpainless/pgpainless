package org.pgpainless.decryption_verification.automaton;

public enum StackAlphabet {
    /**
     * OpenPGP Message.
     */
    msg,
    /**
     * OnePassSignature (in case of BC this represents a OnePassSignatureList).
     */
    ops,
    /**
     * ESK. Not used, as BC combines encrypted data with their encrypted session keys.
     */
    esk,
    /**
     * Special symbol representing the end of the message.
     */
    terminus
}
