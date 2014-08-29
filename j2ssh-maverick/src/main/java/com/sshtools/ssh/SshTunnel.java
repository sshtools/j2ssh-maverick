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

package com.sshtools.ssh;

/**
 * <p>
 * Interface defining the contract for SSH forwarding channels.
 * </p>
 * 
 * <p>
 * Forwarding channels can either be local or remote. Local forwarding transfers
 * data from the local computer to the remote side where it is delivered to the
 * specified host. Remote forwarding is when the remote computer forwards data
 * to the local side.
 * </p>
 * 
 * @author Lee David Painter
 */
public interface SshTunnel extends SshChannel, SshTransport {

	/**
	 * The port to which the data is being forwarded.
	 * 
	 * @return int
	 */
	public int getPort();

	/**
	 * The source ip address of the connection that is being forwarded.
	 * 
	 * @return String
	 */
	public String getListeningAddress();

	/**
	 * The source port of the connection being forwarded.
	 * 
	 * @return int
	 */
	public int getListeningPort();

	/**
	 * The host that made the initial connection to the listening address.
	 * 
	 * @return String
	 */
	public String getOriginatingHost();

	/**
	 * The port of the initial connection.
	 * 
	 * @return int
	 */
	public int getOriginatingPort();

	/**
	 * Determines the type of forwarding channel.
	 * 
	 * @return <tt>true</tt> if the forwarding is local, otherwise
	 *         <tt>false</tt> for remote forwarding.
	 */
	public boolean isLocal();

	/**
	 * Determine if this channel is an X11 forwarding channel.
	 * 
	 * @return boolean
	 */
	public boolean isX11();

	/**
	 * The connection being forwarded (local forwarding) or the destination of
	 * the forwarding (remote forwarding).
	 * 
	 * @return SshTransport
	 */
	public SshTransport getTransport();

	public boolean isLocalEOF();

	public boolean isRemoteEOF();
}
