
package com.sshtools.ssh;

/**
 * An adapter for the <a href="ChannelEventListener.html">ChannelEventListener</a>.
 *
 * @author Lee David Painter
 */
public abstract class ChannelAdapter
    implements ChannelEventListener {

  /* (non-Javadoc)
   * @see com.maverick.ssh.ChannelEventListener#channelOpened(com.maverick.ssh.SshChannel)
   */
  public void channelOpened(SshChannel channel) {

  }

  /* (non-Javadoc)
   * @see com.maverick.ssh.ChannelEventListener#channelClosing(com.maverick.ssh.SshChannel)
   */
  public void channelClosing(SshChannel channel) {

  }

  /* (non-Javadoc)
   * @see com.maverick.ssh.ChannelEventListener#channelClosed(com.maverick.ssh.SshChannel)
   */
  public void channelClosed(SshChannel channel) {

  }
  /* (non-Javadoc)
   * @see com.maverick.ssh.ChannelEventListener#channelEOF(com.maverick.ssh.SshChannel)
   */
  public void channelEOF(SshChannel channel) {

  }

  /* (non-Javadoc)
   * @see com.maverick.ssh.ChannelEventListener#dataReceived(com.maverick.ssh.SshChannel, byte[], int, int)
   */
  public void dataReceived(SshChannel channel, byte[] buf, int off, int len) {

  }

  /* (non-Javadoc)
   * @see com.maverick.ssh.ChannelEventListener#dataSent(com.maverick.ssh.SshChannel, byte[], int, int)
   */
  public void dataSent(SshChannel channel, byte[] buf, int off, int len) {

  }

  /* (non-Javadoc)
   * @see com.maverick.ssh.ChannelEventListener#extendedDataReceived(com.maverick.ssh.SshChannel, byte[], int, int, int)
   */
  public void extendedDataReceived(SshChannel channel,
                                   byte[] data,
                                   int off,
                                   int len,
                                   int extendedDataType) {

  }




}
