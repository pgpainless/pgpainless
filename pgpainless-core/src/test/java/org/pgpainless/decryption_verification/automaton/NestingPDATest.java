// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.automaton;

import org.junit.jupiter.api.Test;
import org.pgpainless.exception.MalformedOpenPgpMessageException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class NestingPDATest {

    /**
     * MSG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testSimpleLiteralMessageIsValid() throws MalformedOpenPgpMessageException {
        NestingPDA automaton = new NestingPDA();
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
        NestingPDA automaton = new NestingPDA();
        automaton.next(InputAlphabet.OnePassSignatures);
        automaton.next(InputAlphabet.LiteralData);
        automaton.next(InputAlphabet.Signatures);
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
        NestingPDA automaton = new NestingPDA();
        automaton.next(InputAlphabet.Signatures);
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
        NestingPDA automaton = new NestingPDA();
        automaton.next(InputAlphabet.OnePassSignatures);
        automaton.next(InputAlphabet.CompressedData);
        automaton.next(InputAlphabet.LiteralData);
        automaton.next(InputAlphabet.EndOfSequence);
        automaton.next(InputAlphabet.Signatures);
        automaton.next(InputAlphabet.EndOfSequence);

        assertTrue(automaton.isValid());
    }

    /**
     * OPS ENC(COMP(COMP(MSG))) SIG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testOpsSignedEncryptedCompressedCompressedMessageIsValid() throws MalformedOpenPgpMessageException {
        NestingPDA automaton = new NestingPDA();
        automaton.next(InputAlphabet.OnePassSignatures);
        automaton.next(InputAlphabet.EncryptedData);
        automaton.next(InputAlphabet.CompressedData);
        automaton.next(InputAlphabet.CompressedData);

        automaton.next(InputAlphabet.LiteralData);

        automaton.next(InputAlphabet.EndOfSequence);
        automaton.next(InputAlphabet.EndOfSequence);
        automaton.next(InputAlphabet.EndOfSequence);
        automaton.next(InputAlphabet.Signatures);
        automaton.next(InputAlphabet.EndOfSequence);

        assertTrue(automaton.isValid());
    }

    /**
     * MSG SIG is invalid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testLiteralPlusSigsFails() throws MalformedOpenPgpMessageException {
        NestingPDA automaton = new NestingPDA();
        automaton.next(InputAlphabet.LiteralData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> automaton.next(InputAlphabet.Signatures));
    }

    /**
     * MSG MSG is invalid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testTwoLiteralDataPacketsFails() throws MalformedOpenPgpMessageException {
        NestingPDA automaton = new NestingPDA();
        automaton.next(InputAlphabet.LiteralData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> automaton.next(InputAlphabet.LiteralData));
    }

    /**
     * OPS COMP(MSG MSG) SIG is invalid (two literal packets are illegal).
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testOPSSignedMessageWithTwoLiteralDataPacketsFails() throws MalformedOpenPgpMessageException {
        NestingPDA automaton = new NestingPDA();
        automaton.next(InputAlphabet.OnePassSignatures);
        automaton.next(InputAlphabet.CompressedData);
        automaton.next(InputAlphabet.LiteralData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> automaton.next(InputAlphabet.LiteralData));
    }

    /**
     * OPS COMP(MSG) MSG SIG is invalid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testOPSSignedMessageWithTwoLiteralDataPacketsFails2() throws MalformedOpenPgpMessageException {
        NestingPDA automaton = new NestingPDA();
        automaton.next(InputAlphabet.OnePassSignatures);
        automaton.next(InputAlphabet.CompressedData);
        automaton.next(InputAlphabet.LiteralData);
        automaton.next(InputAlphabet.EndOfSequence);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> automaton.next(InputAlphabet.LiteralData));
    }

    /**
     * OPS COMP(MSG SIG) is invalid (MSG SIG does not form valid nested message).
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testCorrespondingSignaturesOfOpsSignedMessageAreLayerFurtherDownFails() throws MalformedOpenPgpMessageException {
        NestingPDA automaton = new NestingPDA();
        automaton.next(InputAlphabet.OnePassSignatures);
        automaton.next(InputAlphabet.CompressedData);
        automaton.next(InputAlphabet.LiteralData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> automaton.next(InputAlphabet.Signatures));
    }

    /**
     * Empty COMP is invalid.
     */
    @Test
    public void testEmptyCompressedDataIsInvalid() throws MalformedOpenPgpMessageException {
        NestingPDA automaton = new NestingPDA();
        automaton.next(InputAlphabet.CompressedData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> automaton.next(InputAlphabet.EndOfSequence));
    }

    @Test
    public void testOPSSignedEncryptedCompressedOPSSignedMessageIsValid() throws MalformedOpenPgpMessageException {
        NestingPDA automaton = new NestingPDA();
        automaton.next(InputAlphabet.OnePassSignatures);

        automaton.next(InputAlphabet.EncryptedData);
        automaton.next(InputAlphabet.OnePassSignatures);

        automaton.next(InputAlphabet.CompressedData);
        automaton.next(InputAlphabet.LiteralData);
        automaton.next(InputAlphabet.EndOfSequence);

        automaton.next(InputAlphabet.Signatures);
        automaton.next(InputAlphabet.EndOfSequence);

        automaton.next(InputAlphabet.Signatures);
        automaton.next(InputAlphabet.EndOfSequence);

        assertTrue(automaton.isValid());
    }
}
