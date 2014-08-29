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
 * An adapter for the <a
 * href="ChannelEventListener.html">ChannelEventListener</a>.
 * 
 * @author Lee David Painter
 */
public abstract class ChannelAdapter implements ChannelEventListener {

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.maverick.ssh.ChannelEventListener#channelOpened(com.maverick.ssh.
	 * SshChannel)
	 */
	public void channelOpened(SshChannel channel) {

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.maverick.ssh.ChannelEventListener#channelClosing(com.maverick.ssh
	 * .SshChannel)
	 */
	public void channelClosing(SshChannel channel) {

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.maverick.ssh.ChannelEventListener#channelClosed(com.maverick.ssh.
	 * SshChannel)
	 */
	public void channelClosed(SshChannel channel) {

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.maverick.ssh.ChannelEventListener#channelEOF(com.maverick.ssh.SshChannel
	 * )
	 */
	public void channelEOF(SshChannel channel) {

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.maverick.ssh.ChannelEventListener#dataReceived(com.maverick.ssh.
	 * SshChannel, byte[], int, int)
	 */
	public void dataReceived(SshChannel channel, byte[] buf, int off, int len) {

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.maverick.ssh.ChannelEventListener#dataSent(com.maverick.ssh.SshChannel
	 * , byte[], int, int)
	 */
	public void dataSent(SshChannel channel, byte[] buf, int off, int len) {

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.maverick.ssh.ChannelEventListener#extendedDataReceived(com.maverick
	 * .ssh.SshChannel, byte[], int, int, int)
	 */
	public void extendedDataReceived(SshChannel channel, byte[] data, int off,
			int len, int extendedDataType) {

	}

}
