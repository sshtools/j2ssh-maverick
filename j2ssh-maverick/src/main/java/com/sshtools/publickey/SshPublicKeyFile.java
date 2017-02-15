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
package com.sshtools.publickey;

import java.io.IOException;

import com.sshtools.ssh.components.SshPublicKey;

/**
 * Interface which all public key formats must implement to provide decoding of
 * the public key into a suitable format for the API.
 * 
 * @author Lee David Painter
 */
public interface SshPublicKeyFile {

	/**
	 * Convert the key file into a usable <a
	 * href="../../maverick/ssh/SshPublicKey.html"> SshPublicKey</a>.
	 * 
	 * @return SshPublicKey
	 * @throws IOException
	 */
	public SshPublicKey toPublicKey() throws IOException;

	/**
	 * Get the comment applied to the key file.
	 * 
	 * @return String
	 */
	public String getComment();

	/**
	 * Get the formatted key.
	 * 
	 * @return byte[]
	 * @throws IOException
	 */
	public byte[] getFormattedKey() throws IOException;

}
