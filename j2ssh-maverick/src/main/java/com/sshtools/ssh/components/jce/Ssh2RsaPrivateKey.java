/**
 * Copyright 2003-2014 SSHTOOLS Limited. All Rights Reserved.
 *
 * For product documentation visit https://www.sshtools.com/
 *
 * This file is part of J2SSH Maverick.
 *
 * J2SSH Maverick is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * J2SSH Maverick is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with J2SSH Maverick.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.sshtools.ssh.components.jce;

import java.io.IOException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

import com.sshtools.ssh.components.SshRsaPrivateKey;

/**
 * RSA private key implementation for the SSH2 protocol.
 * 
 * @author Lee David Painter
 * 
 */
public class Ssh2RsaPrivateKey implements SshRsaPrivateKey {

	protected RSAPrivateKey prv;

	public Ssh2RsaPrivateKey(RSAPrivateKey prv) {
		this.prv = prv;
	}

	public Ssh2RsaPrivateKey(BigInteger modulus, BigInteger privateExponent)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		KeyFactory keyFactory = JCEProvider
				.getProviderForAlgorithm(JCEAlgorithms.JCE_RSA) == null ? KeyFactory
				.getInstance(JCEAlgorithms.JCE_RSA) : KeyFactory.getInstance(
				JCEAlgorithms.JCE_RSA,
				JCEProvider.getProviderForAlgorithm(JCEAlgorithms.JCE_RSA));
		RSAPrivateKeySpec spec = new RSAPrivateKeySpec(modulus, privateExponent);
		prv = (RSAPrivateKey) keyFactory.generatePrivate(spec);

	}

	public byte[] sign(byte[] data) throws IOException {
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
			l_sig.update(data);

			return l_sig.sign();
		} catch (Exception e) {
			IOException ex = new IOException("Failed to sign data! "
					+ e.getMessage());
			try {
				Method m = IOException.class.getMethod("initCause",
						new Class[] { Throwable.class });
				m.invoke(ex, new Object[] { e });
			} catch (Throwable e1) {
			}
			throw ex;
		}

	}

	public String getAlgorithm() {
		return "ssh-rsa";
	}

	public BigInteger getModulus() {
		return prv.getModulus();
	}

	public BigInteger getPrivateExponent() {
		return prv.getPrivateExponent();
	}

}
