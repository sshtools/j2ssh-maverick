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

import com.sshtools.logging.Log;

/**
 * @author Lee David Painter
 */
public class ThreadSynchronizer {

	boolean isBlocking;
	Thread blockingThread = null;
	boolean verbose = Boolean.valueOf(
			System.getProperty("maverick.verbose", "false")).booleanValue();

	public ThreadSynchronizer(boolean isBlocking) {
		this.isBlocking = isBlocking;
	}

	public boolean requestBlock(MessageStore store, MessageObserver observer,
			MessageHolder holder) throws InterruptedException {

		holder.msg = store.hasMessage(observer);

		if (holder.msg != null) {
			return false;
		}

		synchronized (ThreadSynchronizer.this) {

			if (Log.isDebugEnabled()) {
				if (verbose) {
					Log.debug(this, "requesting block");
				}
			}

			boolean canBlock = !isBlocking
					|| isBlockOwner(Thread.currentThread());

			if (canBlock) {
				isBlocking = true;
				blockingThread = Thread.currentThread();
			} else {
				if (Log.isDebugEnabled()) {
					if (verbose) {
						Log.debug(this, "can't block so wait");
						Log.debug(this, "isBlocking:" + isBlocking);
						Log.debug(this, "blockowner name:id{"
								+ blockingThread.getName() + "}");
						Log.debug(this, "currentthread name:id{"
								+ Thread.currentThread().getName() + "}");
					}
				}
				wait(1000);
			}
			return canBlock;
		}
	}

	public synchronized boolean isBlockOwner(Thread thread) {
		return blockingThread != null && blockingThread.equals(thread);
	}

	public synchronized void releaseWaiting() {
		notifyAll();
	}

	public synchronized void releaseBlock() {
		/**
		 * Inform the waiting threads that they may take the connection
		 */
		isBlocking = false;
		blockingThread = null;
		notifyAll();
	}

}
