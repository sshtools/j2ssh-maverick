package com.sshtools.ssh.components;

import java.math.BigInteger;

import com.sshtools.ssh.SshException;

/**
 * This interface should be implemented by all RSA public key implementations.
 * 
 * @author Lee David Painter
 */
public interface SshRsaPublicKey extends SshPublicKey {
	BigInteger getModulus();
	BigInteger getPublicExponent();
	int getVersion();
	
	public BigInteger doPublic(BigInteger input) throws SshException;
}
