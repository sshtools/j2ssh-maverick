package com.sshtools.ssh.components;

import java.math.BigInteger;

/**
 * This interface should be implemented by all DSA public key implementations. 
 * 
 * @author Lee David Painter
 *
 */
public interface SshDsaPublicKey extends SshPublicKey {
	public BigInteger getP();
	public BigInteger getQ();
	public BigInteger getG();
	public BigInteger getY();
}
