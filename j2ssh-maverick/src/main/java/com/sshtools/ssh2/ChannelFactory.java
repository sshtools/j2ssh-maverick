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

import com.sshtools.ssh.ChannelOpenException;
import com.sshtools.ssh.SshException;

/**
 * <p>
 * The SSH2 protocol supports many different channel types including sesisons,
 * port forwarding and x11 forwarding; most channels are requested by the client
 * and created by the server however it is possible for the server to request
 * any type of channel from the client, this interface defines the contract for
 * supporting a standard and custom channel creation.
 * </p>
 * 
 * @author Lee David Painter
 */
public interface ChannelFactory {

	/**
	 * Return the supported channel types.
	 * 
	 * @return an array of Strings containing the channel types.
	 */
	public String[] supportedChannelTypes();

	/**
	 * <p>
	 * Create an instance of an SSH channel. The new instance should be
	 * returned, if for any reason the channel cannot be created either because
	 * the channel is not supported or there are not enough resources an
	 * exception is thrown.
	 * </p>
	 * 
	 * @param channeltype
	 * @param requestdata
	 * @return an open channel
	 * @throws ChannelOpenException
	 */
	public Ssh2Channel createChannel(String channeltype, byte[] requestdata)
			throws SshException, ChannelOpenException;
}
