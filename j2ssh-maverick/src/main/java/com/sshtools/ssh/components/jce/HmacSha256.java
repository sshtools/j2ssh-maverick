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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.sshtools.ssh.SshException;

/**
 * SHA-1 message authentication implementation.
 * 
 * @author Lee David Painter
 * 
 */
public class HmacSha256 extends AbstractHmac {

	public HmacSha256() {
		super(JCEAlgorithms.JCE_HMACSHA256, 32);
	}

	public String getAlgorithm() {
		return "hmac-sha256@ssh.com";
	}

	public void init(byte[] keydata) throws SshException {
		try {
			mac = JCEProvider.getProviderForAlgorithm(jceAlgorithm) == null ? Mac
					.getInstance(jceAlgorithm) : Mac.getInstance(jceAlgorithm,
					JCEProvider.getProviderForAlgorithm(jceAlgorithm));

			// Create a key of 16 bytes
			byte[] key = new byte[System.getProperty(
					"miscomputes.ssh2.hmac.keys", "false").equalsIgnoreCase(
					"true") ? 16 : 32];
			System.arraycopy(keydata, 0, key, 0, key.length);

			SecretKeySpec keyspec = new SecretKeySpec(key, jceAlgorithm);
			mac.init(keyspec);
		} catch (Throwable t) {
			throw new SshException(t);
		}
	}

}
