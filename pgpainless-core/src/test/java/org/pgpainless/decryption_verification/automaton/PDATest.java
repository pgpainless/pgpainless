package org.pgpainless.decryption_verification.automaton;

import org.junit.jupiter.api.Test;
import org.pgpainless.exception.MalformedOpenPgpMessageException;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class PDATest {


    /**
     * MSG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testSimpleLiteralMessageIsValid() throws MalformedOpenPgpMessageException {
        PDA automaton = new PDA();
        automaton.next(InputAlphabet.LiteralData);
        automaton.next(InputAlphabet.EndOfSequence);

        assertTrue(automaton.isValid());
    }

    /**
     * OPS MSG SIG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testSimpleOpsSignedMesssageIsValid() throws MalformedOpenPgpMessageException {
        PDA automaton = new PDA();
        automaton.next(InputAlphabet.OnePassSignature);
        automaton.next(InputAlphabet.LiteralData);
        automaton.next(InputAlphabet.Signature);
        automaton.next(InputAlphabet.EndOfSequence);

        assertTrue(automaton.isValid());
    }


    /**
     * SIG MSG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testSimplePrependSignedMessageIsValid() throws MalformedOpenPgpMessageException {
        PDA automaton = new PDA();
        automaton.next(InputAlphabet.Signature);
        automaton.next(InputAlphabet.LiteralData);
        automaton.next(InputAlphabet.EndOfSequence);

        assertTrue(automaton.isValid());
    }


    /**
     * OPS COMP(MSG) SIG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testOPSSignedCompressedMessageIsValid() throws MalformedOpenPgpMessageException {
        PDA automaton = new PDA();
        automaton.next(InputAlphabet.OnePassSignature);
        automaton.next(InputAlphabet.CompressedData);
        // Here would be a nested PDA for the LiteralData packet
        automaton.next(InputAlphabet.Signature);
        automaton.next(InputAlphabet.EndOfSequence);

        assertTrue(automaton.isValid());
    }

}
