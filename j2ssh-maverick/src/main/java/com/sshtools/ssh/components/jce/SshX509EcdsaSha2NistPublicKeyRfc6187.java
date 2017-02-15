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
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPublicKey;

import com.sshtools.logging.Log;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.SshX509PublicKey;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;

public abstract class SshX509EcdsaSha2NistPublicKeyRfc6187 extends Ssh2EcdsaSha2NistPublicKey implements SshX509PublicKey {

 
	Certificate[] certs;

	public SshX509EcdsaSha2NistPublicKeyRfc6187(String name, String spec, String curve) {
		super(name, spec, curve);
	}
	
	public SshX509EcdsaSha2NistPublicKeyRfc6187(ECPublicKey pk) throws IOException {
		super(pk);
	}
	
	public SshX509EcdsaSha2NistPublicKeyRfc6187(Certificate[] chain) throws IOException {
		 super((ECPublicKey)chain[0].getPublicKey());
		this.certs = chain;
	}
	
	public void init(byte[] blob, int start, int len) throws SshException {

		ByteArrayReader reader = new ByteArrayReader(blob, start, len);

		try {

			String alg = reader.readString();
			if (!alg.equals(getAlgorithm())) {
				throw new SshException("Public key blob is not a "
						+ getAlgorithm() + " formatted key [" + alg + "]",
						SshException.BAD_API_USAGE);
			}

			int certificateCount = (int) reader.readInt();

			if(Log.isDebugEnabled()) {
				Log.debug(this, "Expecting chain of " + certificateCount);
			}
			
			if(certificateCount <= 0) {
				throw new SshException( 
						"There are no certificats present in the public key blob",
						SshException.POSSIBLE_CORRUPT_FILE);
			}
			
			this.certs = new Certificate[certificateCount];
			
			for(int i=0;i<certificateCount;i++) {
				byte[] certBlob = reader.readBinaryString();
				CertificateFactory certFactory = CertificateFactory
						.getInstance("X.509");
				certs[i] = certFactory.generateCertificate(new ByteArrayInputStream(certBlob));
			}
			
			this.pub = (ECPublicKey)certs[0].getPublicKey();
		} catch (CertificateException ex) {
			throw new SshException(
					"Failed to generate or read certificate from public key blob: " + ex.getMessage(),
					SshException.INTERNAL_ERROR, ex);
		} catch (IOException ex) {
			throw new SshException(
					"Failed to read public key blob; expected format "
							+ getAlgorithm(), SshException.INTERNAL_ERROR, ex);
		} finally {
			try {
				reader.close();
			} catch (IOException e) {
			}
		}
	}
	
    public Certificate getCertificate() {
        return certs[0];
    }
    
    public Certificate[] getCertificateChain() {
    	return certs;
    }

	public abstract String getAlgorithm();

	public byte[] getEncoded() throws SshException {
		
		ByteArrayWriter writer = new ByteArrayWriter();
		
		try {
			writer.writeString(getAlgorithm());
			writer.writeInt(certs.length);
			
			ByteArrayWriter chain = new ByteArrayWriter();
			try {
				for(Certificate c : certs) {
					chain.writeBinaryString(c.getEncoded());
				}
				
				writer.writeBinaryString(chain.toByteArray());
			} finally {
				chain.close();
			}
			
			// No OCSP responses
			writer.writeInt(0);
			writer.writeInt(0); 
			
			return writer.toByteArray();
		} catch (CertificateEncodingException e) {
			throw new SshException("Failed to encode certificate chain", SshException.INTERNAL_ERROR, e);
		} catch (IOException e) {
			throw new SshException("Failed to write certificate chain", SshException.INTERNAL_ERROR, e);
		} finally {
			try {
				writer.close();
			} catch (IOException e) {
			}
		}
		
	}
}
