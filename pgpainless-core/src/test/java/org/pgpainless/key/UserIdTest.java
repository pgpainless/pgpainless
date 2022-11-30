// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>, 2021 Flowcrypt a.s.
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import org.junit.jupiter.api.Test;
import org.pgpainless.key.util.UserId;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

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
}
