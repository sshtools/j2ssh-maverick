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

package com.sshtools.ssh.message;

import com.sshtools.ssh.SshChannel;
import com.sshtools.ssh.SshException;

/**
 * @author Lee David Painter
 */
public abstract class SshAbstractChannel implements SshChannel {

	public static final int CHANNEL_UNINITIALIZED = 1;
	public static final int CHANNEL_OPEN = 2;
	public static final int CHANNEL_CLOSED = 3;

	protected int channelid = -1;
	protected int state = CHANNEL_UNINITIALIZED;
	protected SshMessageRouter manager;
	protected SshMessageStore ms;

	protected SshMessageStore getMessageStore() throws SshException {
		if (ms == null) {
			throw new SshException("Channel is not initialized!",
					SshException.INTERNAL_ERROR);
		}
		return ms;
	}

	public int getChannelId() {
		return channelid;
	}

	public SshMessageRouter getMessageRouter() {
		return manager;
	}

	protected void init(SshMessageRouter manager, int channelid) {
		this.channelid = channelid;
		this.manager = manager;
		this.ms = new SshMessageStore(manager, this, getStickyMessageIds());
	}

	protected abstract MessageObserver getStickyMessageIds();

	public boolean isClosed() {
		return state == CHANNEL_CLOSED;
	}

	public void idle() {

	}

	protected abstract boolean processChannelMessage(SshChannelMessage m)
			throws SshException;

}
