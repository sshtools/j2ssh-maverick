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
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;

public class SshX509EcdsaSha2Nist521Rfc6187 extends
		SshX509EcdsaSha2NistPublicKeyRfc6187 {

	public SshX509EcdsaSha2Nist521Rfc6187(ECPublicKey pk) throws IOException {
		super(pk);
	}

	public SshX509EcdsaSha2Nist521Rfc6187() {
		super("ecdsa-sha2-nistp521", "SHA512/ECDSA", "secp521r1");
	}

	public SshX509EcdsaSha2Nist521Rfc6187(Certificate[] chain)
			throws IOException {
		super(chain);
	}

	@Override
	public String getAlgorithm() {
		return "x509v3-ecdsa-sha2-nistp521";
	}

}
