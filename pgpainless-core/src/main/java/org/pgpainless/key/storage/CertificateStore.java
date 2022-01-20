package org.pgpainless.key.storage;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

public interface CertificateStore {

    Item get(String identifier) throws IOException;

    Item getIfChanged(String identifier, String tag) throws IOException;
<
    Item insert(InputStream data, MergeCallback merge) throws IOException;

    Item tryInsert(InputStream data, MergeCallback merge) throws IOException;

    Item insertSpecial(String specialName, InputStream data, MergeCallback merge) throws IOException;

    Item tryInsertSpecial(String specialName, InputStream data, MergeCallback merge) throws IOException;

    Iterator<Item> items();

    Iterator<String> fingerprints();
}
