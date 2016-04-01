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
 * You should have received a copy of the GNU General Public License
 * along with J2SSH Maverick.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.sshtools.ssh2;

import java.io.IOException;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.SshPublicKey;

/**
 * Provides a callback when a private key signature is required. This is
 * suitable for use when you do not have direct access to the private key, but
 * know its public key and have access to some mechanism that enables you to
 * request a signature from the corresponding private key (such as an ssh
 * agent).
 * 
 * @author $Author: david $
 */
public interface SignatureGenerator {

	/**
	 * Sign the data using the private key of the public key provided.
	 * 
	 * @param key
	 * @param data
	 * @return byte[]
	 * @throws IOException
	 */
	public byte[] sign(SshPublicKey key, byte[] data) throws SshException;
}
