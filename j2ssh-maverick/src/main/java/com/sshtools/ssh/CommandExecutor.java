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
package com.sshtools.ssh;

import java.io.IOException;

/**
 * Simple command executor class. This class will output commands to a shell in
 * order to execute them synchronously. This requires prior knowledge of the
 * shell prompt and required EOL. For a more detailed implementation use the
 * {@link Shell} class.
 * 
 * @author Lee David Painter
 * @deprecated
 */
public class CommandExecutor {

	SshSession session;
	String eol;
	String prompt;
	String encoding;

	public CommandExecutor(SshSession session, String eol, String promptCmd,
			String prompt, String encoding) throws SshException, IOException {
		this.session = session;
		this.eol = eol;
		this.prompt = prompt;
		this.encoding = encoding;

		executeCommand(promptCmd);

	}

	public String executeCommand(String cmd) throws SshException, IOException {

		try {
			// write the command + eol to the outputstream
			session.getOutputStream().write(cmd.getBytes());
			session.getOutputStream().write(eol.getBytes());

			// read the input stream until reached the end (-1) or reached the
			// promptString
			StringBuffer buf = new StringBuffer();
			int ch;
			do {
				ch = session.getInputStream().read();

				// no more bytes to read so break
				if (ch == -1)
					break;

				// save the character read to the buffer
				buf.append((char) ch);
			} while (!buf.toString().endsWith(prompt));
			// ??? error in return statement when do-while ends from ch==-1.
			return buf.toString().substring(0, buf.length() - prompt.length())
					.trim();
		} catch (SshIOException ex) {
			throw ex.getRealException();
		}
	}
}
