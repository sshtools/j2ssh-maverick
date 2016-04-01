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
package com.sshtools.net;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.Socket;

import com.sshtools.ssh.SocketTimeoutSupport;
import com.sshtools.ssh.SshTransport;

/**
 * Extends a Socket to provide an <a
 * href="../../maverick/ssh/SshTransport.html">SshTransport</a> suitable for use
 * in making connections using the <a
 * href="../../maverick/ssh/SshConnector.html">SshConnector</a>.
 * 
 * @author Lee David Painter
 */
public class SocketTransport extends Socket implements SshTransport,
		SocketTimeoutSupport {

	String hostname;

	/**
	 * Connect the socket.
	 * 
	 * @param hostname
	 * @param port
	 * @throws IOException
	 */
	public SocketTransport(String hostname, int port) throws IOException {
		super(hostname, port);

		this.hostname = hostname;

		/**
		 * The setSendBufferSize and setReceiveBufferSize methods are 1.2 , so
		 * we use reflection so that if we are in 1.1 the code doesn't fall
		 * over.
		 */
		try {
			Method m = Socket.class.getMethod("setSendBufferSize",
					new Class[] { int.class });
			m.invoke(this, new Object[] { new Integer(65535) });
		} catch (Throwable t) {
			// this will error in 1.1 as it is a 1.2 method, so ignore.
		}

		try {
			Method m = Socket.class.getMethod("setReceiveBufferSize",
					new Class[] { int.class });
			m.invoke(this, new Object[] { new Integer(65535) });
		} catch (Throwable t) {
			// this will error in 1.1 as it is a 1.2 method, so ignore.
		}

	}

	/**
	 * Get the hostname of the connected host.
	 */
	public String getHost() {
		return hostname;
	}

	public SshTransport duplicate() throws IOException {
		return new SocketTransport(getHost(), getPort());
	}
}
