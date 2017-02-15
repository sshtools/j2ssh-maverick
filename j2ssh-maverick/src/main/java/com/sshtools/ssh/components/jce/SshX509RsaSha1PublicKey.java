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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import com.sshtools.ssh.SshException;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;

/**
 * Basic implementation of X509 certificate support.
 * 
 * @author not attributable
 */
public class SshX509RsaSha1PublicKey extends Ssh2RsaPublicKey {

	public static final String X509V3_SIGN_RSA_SHA1 = "x509v3-sign-rsa-sha1";
	X509Certificate cert;

	public SshX509RsaSha1PublicKey() {
	}

	public SshX509RsaSha1PublicKey(X509Certificate cert) {
		super((RSAPublicKey) cert.getPublicKey());
		this.cert = cert;
	}

	/**
	 * Get the algorithm name for the public key.
	 * 
	 * @return the algorithm name, for example "ssh-dss"
	 * @todo Implement this com.sshtools.ssh.SshPublicKey method
	 */
	public String getAlgorithm() {
		return X509V3_SIGN_RSA_SHA1;
	}

	/**
	 * Encode the public key into a blob of binary data, the encoded result will
	 * be passed into init to recreate the key.
	 * 
	 * @return an encoded byte array
	 * @throws SshException
	 * @todo Implement this com.sshtools.ssh.SshPublicKey method
	 */
	public byte[] getEncoded() throws SshException {
		ByteArrayWriter baw = new ByteArrayWriter();
		try {
			baw.writeString(getAlgorithm());
			baw.writeBinaryString(cert.getEncoded());
			return baw.toByteArray();
		} catch (Throwable ex) {
			throw new SshException("Failed to encoded key data",
					SshException.INTERNAL_ERROR, ex);
		} finally {
			try {
				baw.close();
			} catch (IOException e) {
			}
		}
	}

	/**
	 * Initialize the public key from a blob of binary data.
	 * 
	 * @param blob
	 *            byte[]
	 * @param start
	 *            int
	 * @param len
	 *            int
	 * @throws SshException
	 * @todo Implement this com.sshtools.ssh.SshPublicKey method
	 */
	public void init(byte[] blob, int start, int len) throws SshException {

		ByteArrayReader bar = new ByteArrayReader(blob, start, len);

		try {

			String header = bar.readString();

			if (!header.equals(X509V3_SIGN_RSA_SHA1)) {
				throw new SshException("The encoded key is not X509 RSA",
						SshException.INTERNAL_ERROR);
			}

			byte[] encoded = bar.readBinaryString();

			ByteArrayInputStream is = new ByteArrayInputStream(encoded);

			CertificateFactory cf = JCEProvider
					.getProviderForAlgorithm(JCEAlgorithms.JCE_X509) == null ? CertificateFactory
					.getInstance(JCEAlgorithms.JCE_X509) : CertificateFactory
					.getInstance(JCEAlgorithms.JCE_X509, JCEProvider
							.getProviderForAlgorithm(JCEAlgorithms.JCE_X509));

			this.cert = (X509Certificate) cf.generateCertificate(is);

			if (!(cert.getPublicKey() instanceof RSAPublicKey))
				throw new SshException(
						"Certificate public key is not an RSA public key!",
						SshException.BAD_API_USAGE);

			this.pubKey = (RSAPublicKey) cert.getPublicKey();

		} catch (Throwable ex) {
			throw new SshException(ex.getMessage(), SshException.JCE_ERROR, ex);
		} finally {
			try {
				bar.close();
			} catch (IOException e) {
			}
		}
	}

	public X509Certificate getCertificate() {
		return cert;
	}

}
