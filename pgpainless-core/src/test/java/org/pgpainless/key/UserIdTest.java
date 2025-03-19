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
                UserId.builder().withName("Juliet Capulet")
                        .build().toString());
    }

    @Test
    public void testFormatNameAndComment() {
        assertEquals(
                "Juliet Capulet (from the play)",
                UserId.builder().withName("Juliet Capulet")
                        .withComment("from the play")
                        .noEmail().build().toString());
    }

    @Test
    public void testFormatNameCommentAndMail() {
        assertEquals("Juliet Capulet (from the play) <juliet@capulet.lit>",
                UserId.builder().withName("Juliet Capulet")
                        .withComment("from the play")
                        .withEmail("juliet@capulet.lit")
                        .build()
                        .toString());
    }

    @Test
    public void testFormatNameAndEmail() {
        assertEquals("Juliet Capulet <juliet@capulet.lit>",
                UserId.builder().withName("Juliet Capulet")
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
        final UserId userId = UserId.builder().withName("John Smith").build();
        assertEquals("John Smith", userId.getName());
        assertNull(userId.getComment());
        assertNull(userId.getEmail());
    }

    @Test
    void testBuilderWithComment() {
        final UserId userId = UserId.builder().withComment("Sales Dept.").build();
        assertNull(userId.getName());
        assertEquals("Sales Dept.", userId.getComment());
        assertNull(userId.getEmail());
    }

    @Test
    void testBuilderWithEmail() {
        final UserId userId = UserId.builder().withEmail("john.smith@example.com").build();
        assertNull(userId.getName());
        assertNull(userId.getComment());
        assertEquals("john.smith@example.com", userId.getEmail());
    }

    @Test
    void testBuilderWithAll() {
        final UserId userId = UserId.builder().withEmail("john.smith@example.com")
                .withName("John Smith")
                .withEmail("john.smith@example.com")
                .withComment("Sales Dept.").build();
        assertEquals("John Smith", userId.getName());
        assertEquals("Sales Dept.", userId.getComment());
        assertEquals("john.smith@example.com", userId.getEmail());
    }

    @Test
    void testBuilderNoName() {
        final UserId.Builder builder = UserId.builder()
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
        final UserId.Builder builder = UserId.builder()
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
        final UserId.Builder builder = UserId.builder()
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
        final UserId userId = UserId.builder()
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
        final UserId userId1 = UserId.builder().withComment(comment).withName(name).withEmail(email).build();
        final UserId userId2 = UserId.builder().withComment(comment).withName(name).withEmail(upperEmail).build();
        assertEquals(userId1, userId2);
    }

    @Test
    void testNotEqualWithDifferentNames() {
        final String name1 = "John Smith";
        final String name2 = "Don Duck";
        final String comment = "Sales Dept.";
        final String email = "john.smith@example.com";
        final UserId userId1 = UserId.builder().withComment(comment).withName(name1).withEmail(email).build();
        final UserId userId2 = UserId.builder().withComment(comment).withName(name2).withEmail(email).build();
        assertNotEquals(userId1, userId2);
    }

    @Test
    void testNotEqualWithDifferentComments() {
        final String name = "John Smith";
        final String comment1 = "Sales Dept.";
        final String comment2 = "Legal Dept.";
        final String email = "john.smith@example.com";
        final UserId userId1 = UserId.builder().withComment(comment1).withName(name).withEmail(email).build();
        final UserId userId2 = UserId.builder().withComment(comment2).withName(name).withEmail(email).build();
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
    public void toStringTest() {
        UserId id = UserId.builder()
                .withName("Alice")
                .withComment("Work Email")
                .withEmail("alice@pgpainless.org")
                .build();

        assertEquals(id.toString(), id.toString());
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
        UserId id4 = UserId.builder().withName("Alice").build();
        UserId id5 = UserId.builder().withName("Alice").withComment("Work Mail").withEmail("alice@pgpainless.org").build();

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
        UserId id4 = UserId.builder().withName("Alice").withComment("Work Email").withEmail("Alice@Pgpainless.Org").build();
        UserId id5 = UserId.builder().withName("alice").withComment("work email").withEmail("alice@pgpainless.org").build();
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

    @Test
    public void parseLatinWithDiacritics() {
        UserId pele = UserId.parse("Pelé@example.com");
        assertEquals("Pelé@example.com", pele.getEmail());

        pele = UserId.parse("Marquez Pelé <Pelé@example.com>");
        assertEquals("Pelé@example.com", pele.getEmail());
        assertEquals("Marquez Pelé", pele.getName());
    }

    @Test
    public void parseGreekAlphabet() {
        UserId dokimi = UserId.parse("δοκιμή@παράδειγμα.δοκιμή");
        assertEquals("δοκιμή@παράδειγμα.δοκιμή", dokimi.getEmail());

        dokimi = UserId.parse("δοκιμή <δοκιμή@παράδειγμα.δοκιμή>");
        assertEquals("δοκιμή", dokimi.getName());
        assertEquals("δοκιμή@παράδειγμα.δοκιμή", dokimi.getEmail());
    }

    @Test
    public void parseTraditionalChinese() {
        UserId womai = UserId.parse("我買@屋企.香港");
        assertEquals("我買@屋企.香港", womai.getEmail());

        womai = UserId.parse("我買 <我買@屋企.香港>");
        assertEquals("我買@屋企.香港", womai.getEmail());
        assertEquals("我買", womai.getName());
    }

    @Test
    public void parseJapanese() {
        UserId ninomiya = UserId.parse("二ノ宮@黒川.日本");
        assertEquals("二ノ宮@黒川.日本", ninomiya.getEmail());

        ninomiya = UserId.parse("二ノ宮 <二ノ宮@黒川.日本>");
        assertEquals("二ノ宮@黒川.日本", ninomiya.getEmail());
        assertEquals("二ノ宮", ninomiya.getName());
    }

    @Test
    public void parseCyrillic() {
        UserId medved = UserId.parse("медведь@с-балалайкой.рф");
        assertEquals("медведь@с-балалайкой.рф", medved.getEmail());

        medved = UserId.parse("медведь <медведь@с-балалайкой.рф>");
        assertEquals("медведь@с-балалайкой.рф", medved.getEmail());
        assertEquals("медведь", medved.getName());
    }

    @Test
    public void parseDevanagari() {
        UserId samparka = UserId.parse("संपर्क@डाटामेल.भारत");
        assertEquals("संपर्क@डाटामेल.भारत", samparka.getEmail());

        samparka = UserId.parse("संपर्क <संपर्क@डाटामेल.भारत>");
        assertEquals("संपर्क@डाटामेल.भारत", samparka.getEmail());
        assertEquals("संपर्क", samparka.getName());
    }

    @Test
    public void parseMailWithPlus() {
        UserId id = UserId.parse("disposable.style.email.with+symbol@example.com");
        assertEquals("disposable.style.email.with+symbol@example.com", id.getEmail());

        id = UserId.parse("Disposable Mail <disposable.style.email.with+symbol@example.com>");
        assertEquals("disposable.style.email.with+symbol@example.com", id.getEmail());
        assertEquals("Disposable Mail", id.getName());
    }

    @Test
    public void parseMailWithHyphen() {
        UserId id = UserId.parse("other.email-with-hyphen@example.com");
        assertEquals("other.email-with-hyphen@example.com", id.getEmail());

        id = UserId.parse("Other Email <other.email-with-hyphen@example.com>");
        assertEquals("other.email-with-hyphen@example.com", id.getEmail());
        assertEquals("Other Email", id.getName());
    }

    @Test
    public void parseMailWithTagAndSorting() {
        UserId id = UserId.parse("user.name+tag+sorting@example.com");
        assertEquals("user.name+tag+sorting@example.com", id.getEmail());

        id = UserId.parse("User Name <user.name+tag+sorting@example.com>");
        assertEquals("user.name+tag+sorting@example.com", id.getEmail());
        assertEquals("User Name", id.getName());
    }

    @Test
    public void parseMailWithSlash() {
        UserId id = UserId.parse("test/test@test.com");
        assertEquals("test/test@test.com", id.getEmail());

        id = UserId.parse("Who uses Slashes <test/test@test.com>");
        assertEquals("test/test@test.com", id.getEmail());
        assertEquals("Who uses Slashes", id.getName());
    }

    @Test
    public void parseDoubleDots() {
        UserId id = UserId.parse("\"john..doe\"@example.org");
        assertEquals("\"john..doe\"@example.org", id.getEmail());

        id = UserId.parse("John Doe <\"john..doe\"@example.org>");
        assertEquals("\"john..doe\"@example.org", id.getEmail());
        assertEquals("John Doe", id.getName());
    }

    @Test
    public void parseBangifiedHostRoute() {
        UserId id = UserId.parse("mailhost!username@example.org");
        assertEquals("mailhost!username@example.org", id.getEmail());

        id = UserId.parse("Bangified Host Route <mailhost!username@example.org>");
        assertEquals("mailhost!username@example.org", id.getEmail());
        assertEquals("Bangified Host Route", id.getName());
    }

    @Test
    public void parsePercentRouted() {
        UserId id = UserId.parse("user%example.com@example.org");
        assertEquals("user%example.com@example.org", id.getEmail());

        id = UserId.parse("User <user%example.com@example.org>");
        assertEquals("user%example.com@example.org", id.getEmail());
        assertEquals("User", id.getName());
    }

    @Test
    public void parseLocalPartEndingWithNonAlphanumericCharacter() {
        UserId id = UserId.parse("user-@example.org");
        assertEquals("user-@example.org", id.getEmail());

        id = UserId.parse("User <user-@example.org>");
        assertEquals("user-@example.org", id.getEmail());
        assertEquals("User", id.getName());
    }

    @Test
    public void parseDomainIsIpAddress() {
        UserId id = UserId.parse("postmaster@[123.123.123.123]");
        assertEquals("postmaster@[123.123.123.123]", id.getEmail());

        id = UserId.parse("Alice (work email) <postmaster@[123.123.123.123]>");
        assertEquals("postmaster@[123.123.123.123]", id.getEmail());
        assertEquals("Alice", id.getName());
        assertEquals("work email", id.getComment());
    }
}
