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
package com.sshtools.ssh.components;

import java.io.IOException;

/**
 * <p>
 * This special cipher implementation provides an unencrypted connection. This
 * is not enabled by default and should be used with caution. To enable and use
 * the cipher you should add the following code before you connect your SSH
 * client.
 * </p>
 * 
 * <blockquote>
 * 
 * <pre>
 * SshConnector con = SshConnector.getInstance();
 * Ssh2Context ssh2Context = (Ssh2Context) con.getContext(SshConnector.SSH2);
 * ssh2Context.supportedCiphers().add(&quot;none&quot;, NoneCipher.class);
 * ssh2Context.setPreferredCipherCS(&quot;none&quot;);
 * ssh2Context.setPreferredCipherSC(&quot;none&quot;);
 * </pre>
 * 
 * <blockquote>
 * 
 * 
 * @author Lee David Painter
 * 
 */
public class NoneCipher extends SshCipher {
	public NoneCipher() {
		super("none");
	}

	/**
	 * Get the cipher block size.
	 * 
	 * @return the block size in bytes.
	 * @todo Implement this com.maverick.ssh.cipher.SshCipher method
	 */
	public int getBlockSize() {
		return 8;
	}

	/**
	 * Initialize the cipher with up to 40 bytes of iv and key data.
	 * 
	 * @param mode
	 *            the mode to operate
	 * @param iv
	 *            the initiaization vector
	 * @param keydata
	 *            the key data
	 * @throws IOException
	 * @todo Implement this com.maverick.ssh.cipher.SshCipher method
	 */
	public void init(int mode, byte[] iv, byte[] keydata) throws IOException {
	}

	/**
	 * Transform the byte array according to the cipher mode; it is legal for
	 * the source and destination arrays to reference the same physical array so
	 * care should be taken in the transformation process to safeguard this
	 * rule.
	 * 
	 * @param src
	 *            byte[]
	 * @param start
	 *            int
	 * @param dest
	 *            byte[]
	 * @param offset
	 *            int
	 * @param len
	 *            int
	 * @throws IOException
	 * @todo Implement this com.maverick.ssh.cipher.SshCipher method
	 */
	public void transform(byte[] src, int start, byte[] dest, int offset,
			int len) throws IOException {
	}
}
