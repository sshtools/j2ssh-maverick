
package com.sshtools.ssh;

/**
 * An event interface that provides notifications of <a href="SshChannel.html">SshChannel</a> events.
 *
 * @author Lee David Painter
 */
public interface ChannelEventListener {

  /**
   * A channel has been opened. This is called once the client has confirmed, or received
   * a confirmation from the server that a channel has been opened.
   *
   * @param channel the opened channel.
   */
  public void channelOpened(SshChannel channel);

  /**
   * A channel is closing. This is called before a channel is confirmed as being
   * closed.
   *
   * @param channel the channel closing.
   */
  public void channelClosing(SshChannel channel);

  /**
   * A channel is closed. This is called when the channel has finally been closed.
   *
   * @param channel the closed channel.
   */
  public void channelClosed(SshChannel channel);


  /**
   * A channel's input is EOF. This is called when the remote side reports that
   * it will not be sending any more data.
   *
   * @param channel SshChannel
   */
  public void channelEOF(SshChannel channel);

  /**
   * A block of data has been received by the channel. This implementation
   * should provide the data but not interfere with normal data processing of the
   * channel.
   * @param channel SshChannel
   * @param data byte[]
   * @param off int
   * @param len int
   */
  public void dataReceived(SshChannel channel, byte[] data, int off, int len);

  /**
   * A block of data has been sent by the channel. This implementation
   * should provide the data but not interfere with normal data processing of the
   * channel.
   * @param channel SshChannel
   * @param data byte[]
   * @param off int
   * @param len int
   */
  public void dataSent(SshChannel channel, byte[] data, int off, int len);

  /**
   * A block of extended data has been received by the channel.
   *
   * @param channel
   * @param data
   * @param off
   * @param len
   * @param extendedDataType the extended data type
   */
  public void extendedDataReceived(SshChannel channel,
                                   byte[] data,
                                   int off,
                                   int len,
                                   int extendedDataType);


}
