# User-IDs

User-IDs are identities that users go by. A User-ID might be a name, an email address or both.
User-IDs can also contain both and even have a comment.

In general, the format of a User-ID is not fixed, so it can contain arbitrary strings.
However, it is agreed upon to use the
Below is a selection of possible User-IDs:

```
Firstname Lastname <email@address.tld> [Comment]
Firstname Lastname
Firstname Lastname [Comment]
<email@address.tld>
<email@address.tld> [Comment]
```

PGPainless comes with a builder class `UserId`, which can be used to safely construct User-IDs:

```java
UserId nameAndEMail = UserId.nameAndEmail("Jane Doe", "jane@pgpainless.org");
assertEquals("Jane Doe <jane@pgpainless.org>", nameAndEmail.toString()):

UserId onlyEmail = UserId.onlyEmail("john@pgpainless.org");
assertEquals("<john@pgpainless.org>", onlyEmail.toString());

UserId full = UserId.newBuilder()
        .withName("Peter Pattern")
        .withEmail("peter@pgpainless.org")
        .withComment("Work Address")
        .build();
assertEquals("Peter Pattern <peter@pgpainless.org> [Work Address]", full.toString());
```