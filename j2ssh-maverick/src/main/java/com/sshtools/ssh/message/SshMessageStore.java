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
package com.sshtools.ssh.message;

import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;

import com.sshtools.logging.Log;
import com.sshtools.ssh.SshException;

/**
 * <p>
 * This class is the central storage location for channel messages; each channel
 * has its own message store and the message pump delivers them here where they
 * are stored in a lightweight linked list.
 * </p>
 * 
 * @author Lee David Painter
 */
public class SshMessageStore implements MessageStore {

	public static final int NO_MESSAGES = -1;
	SshAbstractChannel channel;
	SshMessageRouter manager;
	boolean closed = false;
	SshMessage header = new SshMessage();
	int size = 0;
	MessageObserver stickyMessageObserver;
	boolean verbose = Boolean.valueOf(
			System.getProperty("maverick.verbose", "false")).booleanValue();

	public SshMessageStore(SshMessageRouter manager,
			SshAbstractChannel channel, MessageObserver stickyMessageObserver) {
		this.manager = manager;
		this.channel = channel;
		this.stickyMessageObserver = stickyMessageObserver;
		header.next = header.previous = header;
	}

	/**
	 * 
	 * @param messagefilter
	 * @param timeout
	 * @return SshMessage
	 * @throws IOException
	 * @throws InterruptedIOException
	 */
	public SshMessage nextMessage(MessageObserver observer, long timeout)
			throws SshException, EOFException {

		try {
			SshMessage msg = manager.nextMessage(channel, observer, timeout);
			if (Log.isDebugEnabled()) {
				if (verbose) {
					Log.debug(this, "got managers next message");
				}
			}

			if (msg != null) {
				synchronized (header) {

					if (stickyMessageObserver.wantsNotification(msg)) {
						return msg;
					}

					remove(msg);
					return msg;
				}
			}
		} catch (InterruptedException ex) {
			throw new SshException("The thread was interrupted",
					SshException.INTERNAL_ERROR);
		}

		throw new EOFException(
				"The required message could not be found in the message store");
	}

	public boolean isClosed() {
		synchronized (header) {
			return closed;
		}
	}

	private void remove(SshMessage e) {

		if (e == header) {
			throw new IndexOutOfBoundsException();
		}

		e.previous.next = e.next;
		e.next.previous = e.previous;
		size--;
	}

	public Message hasMessage(MessageObserver observer) {
		if (Log.isDebugEnabled()) {
			if (verbose) {
				Log.debug(this, "waiting for header lock");
			}
		}

		synchronized (header) {

			// this would not seem to take account of header being null, or
			// header.next.next being null, perhaps because these states are not
			// possible? if so document, if not fix.
			SshMessage e = header.next;
			if (e == null) {
				if (Log.isDebugEnabled()) {
					if (verbose) {
						Log.debug(this, "header.next is null");
					}
				}
				return null;
			}

			// cycle through the linked list until we reach the start point
			// (header),
			// checking to see if the message is of a type that the observer is
			// interested in.
			// ??don't seem to look at header though!??
			for (; e != header; e = e.next) {
				if (observer.wantsNotification(e)) {
					if (Log.isDebugEnabled()) {
						if (verbose) {
							Log.debug(this, "found message");
						}
					}
					return e;
				}
			}

			if (Log.isDebugEnabled()) {
				if (verbose) {
					Log.debug(this, "no messages");
				}
			}
			return null;

		}
	}

	public void close() {

		synchronized (header) {
			closed = true;
		}
	}

	void addMessage(SshMessage msg) {
		synchronized (header) {
			// insert this message between header and header.previous, and
			// change their links appropriately
			msg.next = header;
			msg.previous = header.previous;
			// change message before header
			msg.previous.next = msg;
			// change header
			msg.next.previous = msg;
			size++;
		}
	}
}
