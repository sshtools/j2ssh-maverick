/**
 * Copyright 2003-2016 SSHTOOLS Limited. All Rights Reserved.
 *
 * For product documentation visit https://www.sshtools.com/
 *
 * This file is part of J2SSH Maverick.
 *
 * J2SSH Maverick is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * J2SSH Maverick is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with J2SSH Maverick.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.sshtools.ssh.components.jce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;

import javax.crypto.Cipher;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.SshRsaPrivateCrtKey;

/**
 * RSA co-efficient private key implementation for SSH2 protocol.
 * 
 * @author Lee David Painter
 * 
 */
public class Ssh2RsaPrivateCrtKey implements SshRsaPrivateCrtKey {

	protected RSAPrivateCrtKey prv;

	public Ssh2RsaPrivateCrtKey(RSAPrivateCrtKey prv) {
		this.prv = prv;
	}

	public Ssh2RsaPrivateCrtKey(BigInteger modulus, BigInteger publicExponent,
			BigInteger privateExponent, BigInteger primeP, BigInteger primeQ,
			BigInteger primeExponentP, BigInteger primeExponentQ,
			BigInteger crtCoefficient) throws NoSuchAlgorithmException,
			InvalidKeySpecException {

		KeyFactory keyFactory = JCEProvider
				.getProviderForAlgorithm(JCEAlgorithms.JCE_RSA) == null ? KeyFactory
				.getInstance(JCEAlgorithms.JCE_RSA) : KeyFactory.getInstance(
				JCEAlgorithms.JCE_RSA,
				JCEProvider.getProviderForAlgorithm(JCEAlgorithms.JCE_RSA));
		RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(modulus,
				publicExponent, privateExponent, primeP, primeQ,
				primeExponentP, primeExponentQ, crtCoefficient);
		prv = (RSAPrivateCrtKey) keyFactory.generatePrivate(spec);
	}

	public BigInteger doPrivate(BigInteger input) throws SshException {
		try {

			Cipher cipher = JCEProvider
					.getProviderForAlgorithm(JCEAlgorithms.JCE_RSANONEPKCS1PADDING) == null ? Cipher
					.getInstance(JCEAlgorithms.JCE_RSANONEPKCS1PADDING)
					: Cipher.getInstance(
							JCEAlgorithms.JCE_RSANONEPKCS1PADDING,
							JCEProvider
									.getProviderForAlgorithm(JCEAlgorithms.JCE_RSANONEPKCS1PADDING));

			cipher.init(Cipher.DECRYPT_MODE, prv, JCEProvider.getSecureRandom());

			return new BigInteger(cipher.doFinal(input.toByteArray()));
		} catch (Throwable e) {
			throw new SshException(e);
		}
	}

	public BigInteger getCrtCoefficient() {
		return prv.getCrtCoefficient();
	}

	public BigInteger getPrimeExponentP() {
		return prv.getPrimeExponentP();
	}

	public BigInteger getPrimeExponentQ() {
		return prv.getPrimeExponentQ();
	}

	public BigInteger getPrimeP() {
		return prv.getPrimeP();
	}

	public BigInteger getPrimeQ() {
		return prv.getPrimeQ();
	}

	public BigInteger getPublicExponent() {
		return prv.getPublicExponent();
	}

	public BigInteger getModulus() {
		return prv.getModulus();
	}

	public BigInteger getPrivateExponent() {
		return prv.getPrivateExponent();
	}

	public byte[] sign(byte[] msg) throws IOException {
		try {
			Signature l_sig = JCEProvider
					.getProviderForAlgorithm(JCEAlgorithms.JCE_SHA1WithRSA) == null ? Signature
					.getInstance(JCEAlgorithms.JCE_SHA1WithRSA)
					: Signature
							.getInstance(
									JCEAlgorithms.JCE_SHA1WithRSA,
									JCEProvider
											.getProviderForAlgorithm(JCEAlgorithms.JCE_SHA1WithRSA));
			l_sig.initSign(prv);
			l_sig.update(msg);

			return l_sig.sign();
		} catch (Exception e) {
			throw new IOException("Failed to sign data! " + e.getMessage());
		}
	}

	public String getAlgorithm() {
		return "ssh-rsa";
	}
}
