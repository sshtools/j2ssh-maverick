package com.sshtools.ssh.components;

import java.math.BigInteger;

import com.sshtools.ssh.SshException;

/**
 * This interface should be implemented by all RSA private co-efficient
 * private key implementations. 
 *  
 * @author Lee David Painter
 */
public interface SshRsaPrivateCrtKey extends SshRsaPrivateKey {

	public BigInteger getPublicExponent();

	public BigInteger getPrimeP();

	public BigInteger getPrimeQ();

	public BigInteger getPrimeExponentP();

	public BigInteger getPrimeExponentQ();

	public BigInteger getCrtCoefficient();
	
	BigInteger doPrivate(BigInteger input) throws SshException;
}