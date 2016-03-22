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

package com.sshtools.publickey;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.Enumeration;
import java.util.Hashtable;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshIOException;
import com.sshtools.ssh.components.ComponentManager;
import com.sshtools.ssh.components.SshCipher;
import com.sshtools.ssh.components.jce.AES128Cbc;
import com.sshtools.util.Base64;

class PEMWriter extends PEM {
	private String type;
	private Hashtable<String, String> header = new Hashtable<String, String>();
	private byte[] payload;

	/**
	 * Creates a new PEMWriter object.
	 */
	public PEMWriter() {
	}

	/**
	 * 
	 * 
	 * @param w
	 * 
	 * @throws IOException
	 */
	public void write(Writer w) {
		PrintWriter writer = new PrintWriter(w, true);
		writer.println(PEM_BEGIN + type + PEM_BOUNDARY);

		if (!header.isEmpty()) {
			for (Enumeration<String> e = header.keys(); e.hasMoreElements();) {
				String key = e.nextElement();
				String value = header.get(key);

				writer.print(key + ": ");

				if ((key.length() + value.length() + 2) > MAX_LINE_LENGTH) {
					int offset = Math
							.max(MAX_LINE_LENGTH - key.length() - 2, 0);
					writer.println(value.substring(0, offset) + "\\");

					for (; offset < value.length(); offset += MAX_LINE_LENGTH) {
						if ((offset + MAX_LINE_LENGTH) >= value.length()) {
							writer.println(value.substring(offset));
						} else {
							writer.println(value.substring(offset, offset
									+ MAX_LINE_LENGTH)
									+ "\\");
						}
					}
				} else {
					writer.println(value);
				}
			}

			writer.println();
		}

		writer.println(Base64.encodeBytes(payload, false));
		writer.println(PEM_END + type + PEM_BOUNDARY);
	}

	/**
	 * 
	 * 
	 * @param payload
	 * @param passphrase
	 * 
	 */
	public void encryptPayload(byte[] payload, String passphrase)
			throws IOException {
		try {
			if ((passphrase == null) || (passphrase.length() == 0)) {
				// Simple case: no passphrase means no encryption of the private
				// key
				setPayload(payload);
				return;
			}

			byte[] iv = new byte[16];
			ComponentManager.getInstance().getRND().nextBytes(iv);

			StringBuffer ivString = new StringBuffer(16);

			for (int i = 0; i < iv.length; i++) {
				ivString.append(HEX_CHARS[((iv[i] >>> 4) & 0x0f)]);
				ivString.append(HEX_CHARS[iv[i] & 0x0f]);
			}

			header.put(
					"DEK-Info",
					System.getProperty("maverick.privatekey.encryption",
							"AES-128-CBC") + "," + ivString);
			header.put("Proc-Type", "4,ENCRYPTED");

			byte[] keydata = getKeyFromPassphrase(passphrase, iv, 16);

			SshCipher cipher = new AES128Cbc();
			cipher.init(SshCipher.ENCRYPT_MODE, iv, keydata);

			int padding = cipher.getBlockSize()
					- (payload.length % cipher.getBlockSize());
			if (padding > 0) {
				byte[] payloadWithPadding = new byte[payload.length + padding];
				System.arraycopy(payload, 0, payloadWithPadding, 0,
						payload.length);
				for (int i = payload.length; i < payloadWithPadding.length; i++) {
					payloadWithPadding[i] = (byte) padding;
				}
				payload = payloadWithPadding;
			}

			cipher.transform(payload, 0, payload, 0, payload.length);

			setPayload(payload);

		} catch (SshException e) {
			throw new SshIOException(e);
		}
	}

	/**
	 * 
	 * 
	 * @return Hashtable
	 */
	public Hashtable<String, String> getHeader() {
		return header;
	}

	/**
	 * 
	 * 
	 * @return byte[]
	 */
	public byte[] getPayload() {
		return payload;
	}

	/**
	 * 
	 * 
	 * @return String
	 */
	public String getType() {
		return type;
	}

	/**
	 * 
	 * 
	 * @param bs
	 */
	public void setPayload(byte[] bs) {
		payload = bs;
	}

	/**
	 * 
	 * 
	 * @param string
	 */
	public void setType(String string) {
		type = string;
	}
}
