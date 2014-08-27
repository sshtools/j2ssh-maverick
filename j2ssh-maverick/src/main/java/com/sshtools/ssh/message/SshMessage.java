
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
