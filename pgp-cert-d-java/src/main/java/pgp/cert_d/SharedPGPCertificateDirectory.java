package pgp.cert_d;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import pgp.cert_d.exception.BadDataException;
import pgp.cert_d.exception.BadNameException;
import pgp.certificate_store.Item;
import pgp.certificate_store.MergeCallback;

public interface SharedPGPCertificateDirectory {

    Item get(String identifier) throws IOException, BadNameException;

    Item getIfChanged(String identifier, String tag) throws IOException, BadNameException;

    Item insert(InputStream data, MergeCallback merge) throws IOException, BadDataException;

    Item tryInsert(InputStream data, MergeCallback merge) throws IOException, BadDataException;

    Item insertSpecial(String specialName, InputStream data, MergeCallback merge) throws IOException, BadDataException, BadNameException;

    Item tryInsertSpecial(String specialName, InputStream data, MergeCallback merge) throws IOException, BadDataException, BadNameException;

    Iterator<Item> items();

    Iterator<String> fingerprints();
}
