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

import java.io.IOException;

import com.sshtools.ssh.SshException;

/**
 * @author Lee David Painter
 */
public class SshChannelMessage
    extends SshMessage {

  int channelid;
  
  public SshChannelMessage(int channelid, byte[] msg, int off, int len) throws SshException {
	  super(msg, off, len);
	  this.channelid = channelid;
  }
  
  public SshChannelMessage(byte[] msg) throws SshException {
    super(msg);
    try {
        this.channelid = (int) readInt();
    } catch(IOException ex) {
        throw new SshException(SshException.INTERNAL_ERROR,
                               ex);
    }
  }

  int getChannelId() {
    return channelid;
  }
}
