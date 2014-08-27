
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
