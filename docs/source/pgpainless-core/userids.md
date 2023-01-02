# User-IDs

User-IDs are identities that users go by. A User-ID might be a name, an email address or both.
User-IDs can also contain both and even have a comment.

In general, the format of a User-ID is not fixed, so it can contain arbitrary strings.
However, it is agreed upon to use the
Below is a selection of possible User-IDs:

```
Firstname Lastname (Comment) <email@address.tld>
Firstname Lastname
Firstname Lastname (Comment)
<email@address.tld>
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
assertEquals("Peter Pattern (Work Address) <peter@pgpainless.org>", full.toString());
```

If you have a User-ID in form of a string (e.g. because a user provided it via a text field),
you can parse it into its components like this:

```java
String string = "John Doe <john@doe.corp>";
UserId userId = UserId.parse(string);

// Now you can access the different components
assertEquals("John Doe", userId.getName());
assertEquals("john@doe.corp", userId.getEmail());
assertNull(userId.getComment());
```

The method `UserId.parse(String string)` will throw an `IllegalArgumentException` if the User-ID is malformed.
