package com.sshtools.ssh.components;

import java.io.IOException;
import java.math.BigInteger;

/**
 * This interface should be implemented by all DSA private key
 * implementations.
 * 
 * @author Lee David Painter
 *
 */
public interface SshDsaPrivateKey extends SshPrivateKey {

	public abstract BigInteger getX();

	/* (non-Javadoc)
	 * @see com.maverick.ssh.SshPrivateKey#sign(byte[])
	 */
	public abstract byte[] sign(byte[] msg) throws IOException;
	
	
	public SshDsaPublicKey getPublicKey();

}