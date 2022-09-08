// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.junit.jupiter.api.Test;
import org.pgpainless.exception.MalformedOpenPgpMessageException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PushDownAutomatonTest {

    /**
     * MSG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testSimpleLiteralMessageIsValid() throws MalformedOpenPgpMessageException {
        PushdownAutomaton automaton = new PushdownAutomaton();
        automaton.next(PushdownAutomaton.InputAlphabet.LiteralData);
        automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence);

        assertTrue(automaton.isValid());
    }

    /**
     * OPS MSG SIG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testSimpleOpsSignedMesssageIsValid() throws MalformedOpenPgpMessageException {
        PushdownAutomaton automaton = new PushdownAutomaton();
        automaton.next(PushdownAutomaton.InputAlphabet.OnePassSignatures);
        automaton.next(PushdownAutomaton.InputAlphabet.LiteralData);
        automaton.next(PushdownAutomaton.InputAlphabet.Signatures);
        automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence);

        assertTrue(automaton.isValid());
    }

    /**
     * SIG MSG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testSimplePrependSignedMessageIsValid() throws MalformedOpenPgpMessageException {
        PushdownAutomaton automaton = new PushdownAutomaton();
        automaton.next(PushdownAutomaton.InputAlphabet.Signatures);
        automaton.next(PushdownAutomaton.InputAlphabet.LiteralData);
        automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence);

        assertTrue(automaton.isValid());
    }

    /**
     * OPS COMP(MSG) SIG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testOPSSignedCompressedMessageIsValid() throws MalformedOpenPgpMessageException {
        PushdownAutomaton automaton = new PushdownAutomaton();
        automaton.next(PushdownAutomaton.InputAlphabet.OnePassSignatures);
        automaton.next(PushdownAutomaton.InputAlphabet.CompressedData);
        automaton.next(PushdownAutomaton.InputAlphabet.LiteralData);
        automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence);
        automaton.next(PushdownAutomaton.InputAlphabet.Signatures);
        automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence);

        assertTrue(automaton.isValid());
    }

    /**
     * OPS ENC(COMP(COMP(MSG))) SIG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testOpsSignedEncryptedCompressedCompressedMessageIsValid() throws MalformedOpenPgpMessageException {
        PushdownAutomaton automaton = new PushdownAutomaton();
        automaton.next(PushdownAutomaton.InputAlphabet.OnePassSignatures);
        automaton.next(PushdownAutomaton.InputAlphabet.EncryptedData);
        automaton.next(PushdownAutomaton.InputAlphabet.CompressedData);
        automaton.next(PushdownAutomaton.InputAlphabet.CompressedData);

        automaton.next(PushdownAutomaton.InputAlphabet.LiteralData);

        automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence);
        automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence);
        automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence);
        automaton.next(PushdownAutomaton.InputAlphabet.Signatures);
        automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence);

        assertTrue(automaton.isValid());
    }

    /**
     * MSG SIG is invalid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testLiteralPlusSigsFails() throws MalformedOpenPgpMessageException {
        PushdownAutomaton automaton = new PushdownAutomaton();
        automaton.next(PushdownAutomaton.InputAlphabet.LiteralData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> automaton.next(PushdownAutomaton.InputAlphabet.Signatures));
    }

    /**
     * MSG MSG is invalid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testTwoLiteralDataPacketsFails() throws MalformedOpenPgpMessageException {
        PushdownAutomaton automaton = new PushdownAutomaton();
        automaton.next(PushdownAutomaton.InputAlphabet.LiteralData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> automaton.next(PushdownAutomaton.InputAlphabet.LiteralData));
    }

    /**
     * OPS COMP(MSG MSG) SIG is invalid (two literal packets are illegal).
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testOPSSignedMessageWithTwoLiteralDataPacketsFails() throws MalformedOpenPgpMessageException {
        PushdownAutomaton automaton = new PushdownAutomaton();
        automaton.next(PushdownAutomaton.InputAlphabet.OnePassSignatures);
        automaton.next(PushdownAutomaton.InputAlphabet.CompressedData);
        automaton.next(PushdownAutomaton.InputAlphabet.LiteralData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> automaton.next(PushdownAutomaton.InputAlphabet.LiteralData));
    }

    /**
     * OPS COMP(MSG) MSG SIG is invalid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testOPSSignedMessageWithTwoLiteralDataPacketsFails2() throws MalformedOpenPgpMessageException {
        PushdownAutomaton automaton = new PushdownAutomaton();
        automaton.next(PushdownAutomaton.InputAlphabet.OnePassSignatures);
        automaton.next(PushdownAutomaton.InputAlphabet.CompressedData);
        automaton.next(PushdownAutomaton.InputAlphabet.LiteralData);
        automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> automaton.next(PushdownAutomaton.InputAlphabet.LiteralData));
    }

    /**
     * OPS COMP(MSG SIG) is invalid (MSG SIG does not form valid nested message).
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testCorrespondingSignaturesOfOpsSignedMessageAreLayerFurtherDownFails() throws MalformedOpenPgpMessageException {
        PushdownAutomaton automaton = new PushdownAutomaton();
        automaton.next(PushdownAutomaton.InputAlphabet.OnePassSignatures);
        automaton.next(PushdownAutomaton.InputAlphabet.CompressedData);
        automaton.next(PushdownAutomaton.InputAlphabet.LiteralData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> automaton.next(PushdownAutomaton.InputAlphabet.Signatures));
    }

    /**
     * Empty COMP is invalid.
     */
    @Test
    public void testEmptyCompressedDataIsInvalid() throws MalformedOpenPgpMessageException {
        PushdownAutomaton automaton = new PushdownAutomaton();
        automaton.next(PushdownAutomaton.InputAlphabet.CompressedData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence));
    }

    @Test
    public void testOPSSignedEncryptedCompressedOPSSignedMessageIsValid() throws MalformedOpenPgpMessageException {
        PushdownAutomaton automaton = new PushdownAutomaton();
        automaton.next(PushdownAutomaton.InputAlphabet.OnePassSignatures);

        automaton.next(PushdownAutomaton.InputAlphabet.EncryptedData);
        automaton.next(PushdownAutomaton.InputAlphabet.OnePassSignatures);

        automaton.next(PushdownAutomaton.InputAlphabet.CompressedData);
        automaton.next(PushdownAutomaton.InputAlphabet.LiteralData);
        automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence);

        automaton.next(PushdownAutomaton.InputAlphabet.Signatures);
        automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence);

        automaton.next(PushdownAutomaton.InputAlphabet.Signatures);
        automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence);

        assertTrue(automaton.isValid());
    }
}
