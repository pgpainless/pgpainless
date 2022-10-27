// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.pgpainless.exception.MalformedOpenPgpMessageException;

public class PDATest {


    /**
     * MSG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testSimpleLiteralMessageIsValid() throws MalformedOpenPgpMessageException {
        PDA check = new PDA();
        check.next(InputSymbol.LiteralData);
        check.next(InputSymbol.EndOfSequence);

        assertTrue(check.isValid());
    }

    /**
     * OPS MSG SIG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testSimpleOpsSignedMesssageIsValid() throws MalformedOpenPgpMessageException {
        PDA check = new PDA();
        check.next(InputSymbol.OnePassSignature);
        check.next(InputSymbol.LiteralData);
        check.next(InputSymbol.Signature);
        check.next(InputSymbol.EndOfSequence);

        assertTrue(check.isValid());
    }


    /**
     * SIG MSG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testSimplePrependSignedMessageIsValid() throws MalformedOpenPgpMessageException {
        PDA check = new PDA();
        check.next(InputSymbol.Signature);
        check.next(InputSymbol.LiteralData);
        check.next(InputSymbol.EndOfSequence);

        assertTrue(check.isValid());
    }


    /**
     * OPS COMP(MSG) SIG is valid.
     *
     * @throws MalformedOpenPgpMessageException fail
     */
    @Test
    public void testOPSSignedCompressedMessageIsValid() throws MalformedOpenPgpMessageException {
        PDA check = new PDA();
        check.next(InputSymbol.OnePassSignature);
        check.next(InputSymbol.CompressedData);
        // Here would be a nested PDA for the LiteralData packet
        check.next(InputSymbol.Signature);
        check.next(InputSymbol.EndOfSequence);

        assertTrue(check.isValid());
    }

    @Test
    public void testOPSSignedEncryptedMessageIsValid() {
        PDA check = new PDA();
        check.next(InputSymbol.OnePassSignature);
        check.next(InputSymbol.EncryptedData);
        check.next(InputSymbol.Signature);
        check.next(InputSymbol.EndOfSequence);
        assertTrue(check.isValid());
    }

    @Test
    public void anyInputAfterEOSIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.LiteralData);
        check.next(InputSymbol.EndOfSequence);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.Signature));
    }

    @Test
    public void testEncryptedMessageWithAppendedStandaloneSigIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.EncryptedData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.Signature));
    }

    @Test
    public void testOPSSignedEncryptedMessageWithMissingSigIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.OnePassSignature);
        check.next(InputSymbol.EncryptedData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.EndOfSequence));
    }

    @Test
    public void testTwoLiteralDataIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.LiteralData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.LiteralData));
    }

    @Test
    public void testTrailingSigIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.LiteralData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.Signature));
    }

    @Test
    public void testOPSAloneIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.OnePassSignature);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.EndOfSequence));
    }

    @Test
    public void testOPSLitWithMissingSigIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.OnePassSignature);
        check.next(InputSymbol.LiteralData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.EndOfSequence));
    }

    @Test
    public void testCompressedMessageWithStandalongAppendedSigIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.CompressedData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.Signature));
    }

    @Test
    public void testOPSCompressedDataWithMissingSigIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.OnePassSignature);
        check.next(InputSymbol.CompressedData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.EndOfSequence));
    }

    @Test
    public void testCompressedMessageFollowedByTrailingLiteralDataIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.CompressedData);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.LiteralData));
    }

    @Test
    public void testOPSWithPrependedSigIsValid() {
        PDA check = new PDA();
        check.next(InputSymbol.Signature);
        check.next(InputSymbol.OnePassSignature);
        check.next(InputSymbol.LiteralData);
        check.next(InputSymbol.Signature);
        check.next(InputSymbol.EndOfSequence);

        assertTrue(check.isValid());
    }

    @Test
    public void testPrependedSigInsideOPSSignedMessageIsValid() {
        PDA check = new PDA();
        check.next(InputSymbol.OnePassSignature);
        check.next(InputSymbol.Signature);
        check.next(InputSymbol.LiteralData);
        check.next(InputSymbol.Signature);
        check.next(InputSymbol.EndOfSequence);

        assertTrue(check.isValid());
    }
}
