
package com.sshtools.ssh.message;

import com.sshtools.ssh.SshChannel;
import com.sshtools.ssh.SshException;

/**
 * @author Lee David Painter
 */
public abstract class SshAbstractChannel
    implements SshChannel {

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
