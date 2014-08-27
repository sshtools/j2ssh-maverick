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

import com.sshtools.util.ByteArrayReader;

/**
 *
 * @author Lee David Painter
 */
public class SshMessage extends ByteArrayReader implements Message {

  int messageid;
  byte[] msg;
  SshMessage next;
  SshMessage previous;

  // Private constrcutor for Linked List
  SshMessage() {
      super(new byte[] { });
  }

  public SshMessage(byte[] msg, int off, int len) {
	  super(msg, off, len);
  }
  
  public SshMessage(byte[] msg) {
    super(msg);
    this.messageid = read();
  }

  public int getMessageId() {
    return messageid;
  }


}
