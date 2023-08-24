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
        check.next(InputSymbol.LITERAL_DATA);
        check.next(InputSymbol.END_OF_SEQUENCE);

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
        check.next(InputSymbol.ONE_PASS_SIGNATURE);
        check.next(InputSymbol.LITERAL_DATA);
        check.next(InputSymbol.SIGNATURE);
        check.next(InputSymbol.END_OF_SEQUENCE);

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
        check.next(InputSymbol.SIGNATURE);
        check.next(InputSymbol.LITERAL_DATA);
        check.next(InputSymbol.END_OF_SEQUENCE);

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
        check.next(InputSymbol.ONE_PASS_SIGNATURE);
        check.next(InputSymbol.COMPRESSED_DATA);
        // Here would be a nested PDA for the LiteralData packet
        check.next(InputSymbol.SIGNATURE);
        check.next(InputSymbol.END_OF_SEQUENCE);

        assertTrue(check.isValid());
    }

    @Test
    public void testOPSSignedEncryptedMessageIsValid() {
        PDA check = new PDA();
        check.next(InputSymbol.ONE_PASS_SIGNATURE);
        check.next(InputSymbol.ENCRYPTED_DATA);
        check.next(InputSymbol.SIGNATURE);
        check.next(InputSymbol.END_OF_SEQUENCE);
        assertTrue(check.isValid());
    }

    @Test
    public void anyInputAfterEOSIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.LITERAL_DATA);
        check.next(InputSymbol.END_OF_SEQUENCE);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.SIGNATURE));
    }

    @Test
    public void testEncryptedMessageWithAppendedStandaloneSigIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.ENCRYPTED_DATA);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.SIGNATURE));
    }

    @Test
    public void testOPSSignedEncryptedMessageWithMissingSigIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.ONE_PASS_SIGNATURE);
        check.next(InputSymbol.ENCRYPTED_DATA);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.END_OF_SEQUENCE));
    }

    @Test
    public void testTwoLiteralDataIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.LITERAL_DATA);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.LITERAL_DATA));
    }

    @Test
    public void testTrailingSigIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.LITERAL_DATA);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.SIGNATURE));
    }

    @Test
    public void testOPSAloneIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.ONE_PASS_SIGNATURE);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.END_OF_SEQUENCE));
    }

    @Test
    public void testOPSLitWithMissingSigIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.ONE_PASS_SIGNATURE);
        check.next(InputSymbol.LITERAL_DATA);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.END_OF_SEQUENCE));
    }

    @Test
    public void testCompressedMessageWithStandalongAppendedSigIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.COMPRESSED_DATA);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.SIGNATURE));
    }

    @Test
    public void testOPSCompressedDataWithMissingSigIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.ONE_PASS_SIGNATURE);
        check.next(InputSymbol.COMPRESSED_DATA);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.END_OF_SEQUENCE));
    }

    @Test
    public void testCompressedMessageFollowedByTrailingLiteralDataIsNotValid() {
        PDA check = new PDA();
        check.next(InputSymbol.COMPRESSED_DATA);
        assertThrows(MalformedOpenPgpMessageException.class,
                () -> check.next(InputSymbol.LITERAL_DATA));
    }

    @Test
    public void testOPSWithPrependedSigIsValid() {
        PDA check = new PDA();
        check.next(InputSymbol.SIGNATURE);
        check.next(InputSymbol.ONE_PASS_SIGNATURE);
        check.next(InputSymbol.LITERAL_DATA);
        check.next(InputSymbol.SIGNATURE);
        check.next(InputSymbol.END_OF_SEQUENCE);

        assertTrue(check.isValid());
    }

    @Test
    public void testPrependedSigInsideOPSSignedMessageIsValid() {
        PDA check = new PDA();
        check.next(InputSymbol.ONE_PASS_SIGNATURE);
        check.next(InputSymbol.SIGNATURE);
        check.next(InputSymbol.LITERAL_DATA);
        check.next(InputSymbol.SIGNATURE);
        check.next(InputSymbol.END_OF_SEQUENCE);

        assertTrue(check.isValid());
    }
}
