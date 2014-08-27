
package com.sshtools.publickey;

/**
 *
 * <p>Thrown by an {@link SshPrivateKeyFile} when it detects that the
 * passphrase supplied was invalid.</p>
 *
 * @author Lee David Painter
 */
public class InvalidPassphraseException extends Exception {

	private static final long serialVersionUID = 1L;

	public InvalidPassphraseException() {
        super("The passphrase supplied was invalid!");
    }
    
    public InvalidPassphraseException(Exception ex) {
    	super(ex.getMessage());
    }
}
