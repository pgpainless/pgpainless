package pgp.cert_d.exception;

/**
 * The base dir cannot possibly contain a store.
 */
public class NotAStoreException extends Exception {

    public NotAStoreException() {
        super();
    }

    public NotAStoreException(String message) {
        super(message);
    }
}
