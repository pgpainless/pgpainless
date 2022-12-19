// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>, 2021 Flowcrypt a.s.
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Comparator;

import org.junit.jupiter.api.Test;
import org.pgpainless.key.util.UserId;

public class UserIdTest {

    @Test
    public void testFormatOnlyName() {
        assertEquals(
                "Juliet Capulet",
                UserId.newBuilder().withName("Juliet Capulet")
                        .build().toString());
    }

    @Test
    public void testFormatNameAndComment() {
        assertEquals(
                "Juliet Capulet (from the play)",
                UserId.newBuilder().withName("Juliet Capulet")
                        .withComment("from the play")
                        .noEmail().build().toString());
    }

    @Test
    public void testFormatNameCommentAndMail() {
        assertEquals("Juliet Capulet (from the play) <juliet@capulet.lit>",
                UserId.newBuilder().withName("Juliet Capulet")
                        .withComment("from the play")
                        .withEmail("juliet@capulet.lit")
                        .build()
                        .toString());
    }

    @Test
    public void testFormatNameAndEmail() {
        assertEquals("Juliet Capulet <juliet@capulet.lit>",
                UserId.newBuilder().withName("Juliet Capulet")
                        .noComment()
                        .withEmail("juliet@capulet.lit")
                        .build()
                        .toString());
    }

    @Test
    public void testNameAndEmail() {
        UserId userId = UserId.nameAndEmail("Maurice Moss", "moss.m@reynholm.co.uk");
        assertEquals("Maurice Moss <moss.m@reynholm.co.uk>", userId.toString());
    }

    @Test
    void testBuilderWithName() {
        final UserId userId = UserId.newBuilder().withName("John Smith").build();
        assertEquals("John Smith", userId.getName());
        assertNull(userId.getComment());
        assertNull(userId.getEmail());
    }

    @Test
    void testBuilderWithComment() {
        final UserId userId = UserId.newBuilder().withComment("Sales Dept.").build();
        assertNull(userId.getName());
        assertEquals("Sales Dept.", userId.getComment());
        assertNull(userId.getEmail());
    }

    @Test
    void testBuilderWithEmail() {
        final UserId userId = UserId.newBuilder().withEmail("john.smith@example.com").build();
        assertNull(userId.getName());
        assertNull(userId.getComment());
        assertEquals("john.smith@example.com", userId.getEmail());
    }

    @Test
    void testBuilderWithAll() {
        final UserId userId = UserId.newBuilder().withEmail("john.smith@example.com")
                .withName("John Smith")
                .withEmail("john.smith@example.com")
                .withComment("Sales Dept.").build();
        assertEquals("John Smith", userId.getName());
        assertEquals("Sales Dept.", userId.getComment());
        assertEquals("john.smith@example.com", userId.getEmail());
    }

    @Test
    void testBuilderNoName() {
        final UserId.Builder builder = UserId.newBuilder()
                .withEmail("john.smith@example.com")
                .withName("John Smith")
                .withComment("Sales Dept.").build().toBuilder();
        final UserId userId = builder.noName().build();
        assertNull(userId.getName());
        assertEquals("Sales Dept.", userId.getComment());
        assertEquals("john.smith@example.com", userId.getEmail());
    }

    @Test
    void testBuilderNoComment() {
        final UserId.Builder builder = UserId.newBuilder()
                .withEmail("john.smith@example.com")
                .withName("John Smith")
                .withComment("Sales Dept.").build().toBuilder();
        final UserId userId = builder.noComment().build();
        assertEquals("John Smith", userId.getName());
        assertNull(userId.getComment());
        assertEquals("john.smith@example.com", userId.getEmail());
    }

    @Test
    void testBuilderNoEmail() {
        final UserId.Builder builder = UserId.newBuilder()
                .withEmail("john.smith@example.com")
                .withName("John Smith")
                .withComment("Sales Dept.").build().toBuilder();
        final UserId userId = builder.noEmail().build();
        assertEquals("John Smith", userId.getName());
        assertEquals("Sales Dept.", userId.getComment());
        assertNull(userId.getEmail());
    }

    @Test
    void testEmailOnlyFormatting() {
        final UserId userId = UserId.onlyEmail("john.smith@example.com");
        assertEquals("<john.smith@example.com>", userId.toString());
    }

    @Test
    void testEmptyNameAndValidEmailFormatting() {
        final UserId userId = UserId.nameAndEmail("", "john.smith@example.com");
        assertEquals("<john.smith@example.com>", userId.toString());
    }

    @Test
    void testEmptyNameAndEmptyCommentAndValidEmailFormatting() {
        final UserId userId = UserId.newBuilder()
                .withComment("")
                .withName("")
                .withEmail("john.smith@example.com")
                .build();
        assertEquals("<john.smith@example.com>", userId.toString());
    }

    @Test
    void testEqualsWithDifferentCaseEmails() {
        final String name = "John Smith";
        final String comment = "Sales Dept.";
        final String email = "john.smith@example.com";
        final String upperEmail = email.toUpperCase();
        final UserId userId1 = UserId.newBuilder().withComment(comment).withName(name).withEmail(email).build();
        final UserId userId2 = UserId.newBuilder().withComment(comment).withName(name).withEmail(upperEmail).build();
        assertEquals(userId1, userId2);
    }

    @Test
    void testNotEqualWithDifferentNames() {
        final String name1 = "John Smith";
        final String name2 = "Don Duck";
        final String comment = "Sales Dept.";
        final String email = "john.smith@example.com";
        final UserId userId1 = UserId.newBuilder().withComment(comment).withName(name1).withEmail(email).build();
        final UserId userId2 = UserId.newBuilder().withComment(comment).withName(name2).withEmail(email).build();
        assertNotEquals(userId1, userId2);
    }

    @Test
    void testNotEqualWithDifferentComments() {
        final String name = "John Smith";
        final String comment1 = "Sales Dept.";
        final String comment2 = "Legal Dept.";
        final String email = "john.smith@example.com";
        final UserId userId1 = UserId.newBuilder().withComment(comment1).withName(name).withEmail(email).build();
        final UserId userId2 = UserId.newBuilder().withComment(comment2).withName(name).withEmail(email).build();
        assertNotEquals(userId1, userId2);
    }

    @Test
    public void testLength() {
        UserId id = UserId.nameAndEmail("Alice", "alice@pgpainless.org");
        assertEquals(28, id.length());
    }

    @Test
    public void testSubSequence() {
        UserId id = UserId.onlyEmail("alice@pgpainless.org");
        assertEquals("alice@pgpainless.org", id.subSequence(1, id.length() - 1));
    }

    @Test
    public void asStringTest() {
        UserId id = UserId.newBuilder()
                .withName("Alice")
                .withComment("Work Email")
                .withEmail("alice@pgpainless.org")
                .build();

        // noinspection deprecation
        assertEquals(id.toString(), id.asString());
    }

    @Test
    public void charAtTest() {
        UserId id = UserId.onlyEmail("alice@pgpainless.org");
        assertEquals('<', id.charAt(0));
        assertEquals('>', id.charAt(id.length() - 1));
    }

    @Test
    public void defaultCompareTest() {
        UserId id1 = UserId.onlyEmail("alice@pgpainless.org");
        UserId id2 = UserId.onlyEmail("alice@gnupg.org");
        UserId id3 = UserId.nameAndEmail("Alice", "alice@pgpainless.org");
        UserId id3_ = UserId.nameAndEmail("Alice", "alice@pgpainless.org");
        UserId id4 = UserId.newBuilder().withName("Alice").build();
        UserId id5 = UserId.newBuilder().withName("Alice").withComment("Work Mail").withEmail("alice@pgpainless.org").build();

        assertEquals(id3.hashCode(), id3_.hashCode());
        assertNotEquals(id2.hashCode(), id3.hashCode());

        Comparator<UserId> c = new UserId.DefaultComparator();
        assertEquals(0, UserId.compare(null, null, c));
        assertEquals(0, UserId.compare(id1, id1, c));
        assertNotEquals(0, UserId.compare(id1, null, c));
        assertNotEquals(0, UserId.compare(null, id1, c));
        assertNotEquals(0, UserId.compare(id1, id2, c));
        assertNotEquals(0, UserId.compare(id2, id1, c));
        assertNotEquals(0, UserId.compare(id1, id3, c));
        assertNotEquals(0, UserId.compare(id1, id4, c));
        assertNotEquals(0, UserId.compare(id4, id1, c));
        assertNotEquals(0, UserId.compare(id2, id3, c));
        assertNotEquals(0, UserId.compare(id1, id5, c));
        assertNotEquals(0, UserId.compare(id5, id1, c));
        assertNotEquals(0, UserId.compare(id3, id5, c));
        assertNotEquals(0, UserId.compare(id5, id3, c));
        assertEquals(0, UserId.compare(id3, id3, c));
        assertEquals(0, UserId.compare(id3, id3_, c));
    }

    @Test
    public void defaultIgnoreCaseCompareTest() {
        UserId id1 = UserId.nameAndEmail("Alice", "alice@pgpainless.org");
        UserId id2 = UserId.nameAndEmail("alice", "alice@pgpainless.org");
        UserId id3 = UserId.nameAndEmail("Alice", "Alice@Pgpainless.Org");
        UserId id4 = UserId.newBuilder().withName("Alice").withComment("Work Email").withEmail("Alice@Pgpainless.Org").build();
        UserId id5 = UserId.newBuilder().withName("alice").withComment("work email").withEmail("alice@pgpainless.org").build();
        UserId id6 = UserId.nameAndEmail("Bob", "bob@pgpainless.org");

        Comparator<UserId> c = new UserId.DefaultIgnoreCaseComparator();
        assertEquals(0, UserId.compare(id1, id2, c));
        assertEquals(0, UserId.compare(id1, id3, c));
        assertEquals(0, UserId.compare(id2, id3, c));
        assertEquals(0, UserId.compare(null, null, c));
        assertEquals(0, UserId.compare(id1, id1, c));
        assertEquals(0, UserId.compare(id4, id4, c));
        assertEquals(0, UserId.compare(id4, id5, c));
        assertEquals(0, UserId.compare(id5, id4, c));
        assertNotEquals(0, UserId.compare(null, id1, c));
        assertNotEquals(0, UserId.compare(id1, null, c));
        assertNotEquals(0, UserId.compare(id1, id4, c));
        assertNotEquals(0, UserId.compare(id4, id1, c));
        assertNotEquals(0, UserId.compare(id1, id6, c));
        assertNotEquals(0, UserId.compare(id6, id1, c));
    }

    @Test
    public void parseNameAndEmail() {
        UserId id = UserId.parse("Alice <alice@pgpainless.org>");

        assertEquals("Alice", id.getName());
        assertNull(id.getComment());
        assertEquals("alice@pgpainless.org", id.getEmail());

        assertEquals("Alice <alice@pgpainless.org>", id.toString());
    }

    @Test
    public void parseNameCommentAndEmail() {
        UserId id = UserId.parse("Alice (work mail) <alice@pgpainless.org>");

        assertEquals("Alice", id.getName());
        assertEquals("work mail", id.getComment());
        assertEquals("alice@pgpainless.org", id.getEmail());

        assertEquals("Alice (work mail) <alice@pgpainless.org>", id.toString());
    }

    @Test
    public void parseLongNameAndEmail() {
        UserId id = UserId.parse("Alice von Painleicester <alice@pgpainless.org>");

        assertEquals("Alice von Painleicester", id.getName());
        assertNull(id.getComment());
        assertEquals("alice@pgpainless.org", id.getEmail());

        assertEquals("Alice von Painleicester <alice@pgpainless.org>", id.toString());
    }

    @Test
    public void parseLongNameCommentAndEmail() {
        UserId id = UserId.parse("Alice von Painleicester (work email) <alice@pgpainless.org>");

        assertEquals("Alice von Painleicester", id.getName());
        assertEquals("work email", id.getComment());
        assertEquals("alice@pgpainless.org", id.getEmail());

        assertEquals("Alice von Painleicester (work email) <alice@pgpainless.org>", id.toString());
    }

    @Test
    public void parseQuotedNameAndEmail() {
        UserId id = UserId.parse("\"Alice\" <alice@pgpainless.org>");

        assertEquals("Alice", id.getName());
        assertNull(id.getComment());
        assertEquals("alice@pgpainless.org", id.getEmail());

        assertEquals("\"Alice\" <alice@pgpainless.org>", id.toString());
    }

    @Test
    public void parseQuotedNameCommentAndEmail() {
        UserId id = UserId.parse("\"Alice\" (work email) <alice@pgpainless.org>");

        assertEquals("Alice", id.getName());
        assertEquals("work email", id.getComment());
        assertEquals("alice@pgpainless.org", id.getEmail());

        assertEquals("\"Alice\" (work email) <alice@pgpainless.org>", id.toString());
    }

    @Test
    public void parseLongQuotedNameAndEmail() {
        UserId id = UserId.parse("\"Alice Mac Painlester\" <alice@pgpainless.org>");

        assertEquals("Alice Mac Painlester", id.getName());
        assertNull(id.getComment());
        assertEquals("alice@pgpainless.org", id.getEmail());

        assertEquals("\"Alice Mac Painlester\" <alice@pgpainless.org>", id.toString());
    }

    @Test
    public void parseLongQuotedNameCommentAndEmail() {
        UserId id = UserId.parse("\"Alice Mac Painlester\" (work email) <alice@pgpainless.org>");

        assertEquals("Alice Mac Painlester", id.getName());
        assertEquals("work email", id.getComment());
        assertEquals("alice@pgpainless.org", id.getEmail());

        assertEquals("\"Alice Mac Painlester\" (work email) <alice@pgpainless.org>", id.toString());
    }

    @Test
    public void parseEmailOnly() {
        UserId id = UserId.parse("alice@pgpainless.org");

        assertNull(id.getName());
        assertNull(id.getComment());
        assertEquals("alice@pgpainless.org", id.getEmail());

        assertEquals("<alice@pgpainless.org>", id.toString());
    }

    @Test
    public void parseBracketedEmailOnly() {
        UserId id = UserId.parse("<alice@pgpainless.org>");

        assertNull(id.getName());
        assertNull(id.getComment());
        assertEquals("alice@pgpainless.org", id.getEmail());

        assertEquals("<alice@pgpainless.org>", id.toString());
    }
}
