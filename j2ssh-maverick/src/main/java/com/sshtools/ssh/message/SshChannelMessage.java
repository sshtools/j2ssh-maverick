
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
