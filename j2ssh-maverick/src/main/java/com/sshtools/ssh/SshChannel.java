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

import com.sshtools.ssh.message.SshMessageRouter;


/**
 *
 * <p>The base interface for all SSH channels. SSH Channels enable the multiplexing of several unique
 * data channels over a single SSH connection, each channel is identified by an unique ID and provides
 * a set of IO streams for sending and recieving data.</p>
 *
 * @author Lee David Painter
 */
public interface SshChannel extends SshIO {

  /**
   * Get the id of this channel.
   * @return the channel id
   */
  public int getChannelId();

  /**
   * Evaluate whether the channel is closed.
   * @return <code>true</code> if the channel is closed, otherwise <code>false</code>
   */
  public boolean isClosed();

  /**
   * Provides an event listening mechanism.
   * @param listener
   */
  public void addChannelEventListener(ChannelEventListener listener);

  /**
   * Automatically consume input data
   * @param autoConsumeInput boolean
   */
  public void setAutoConsumeInput(boolean autoConsumeInput);
  
  /**
   * Returns the message router instance to which this channel belongs.
   * @return
   */
  public SshMessageRouter getMessageRouter();

}
