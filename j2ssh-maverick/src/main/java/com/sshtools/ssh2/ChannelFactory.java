
package com.sshtools.ssh2;

import com.sshtools.ssh.ChannelOpenException;
import com.sshtools.ssh.SshException;

/**
     * <p>The SSH2 protocol supports many different channel types including sesisons,
     * port forwarding and x11 forwarding; most channels are requested by the client
 * and created by the server however it is possible for the server to request
 * any type of channel from the client, this interface defines the contract for
 * supporting a standard and custom channel creation.
 * </p>
 *
 * @author Lee David Painter
 */
public interface ChannelFactory {

  /**
   * Return the supported channel types.
   *
   * @return an array of Strings containing the channel types.
   */
  public String[] supportedChannelTypes();

  /**
   * <p>Create an instance of an SSH channel. The new instance should
   * be returned, if for any reason the channel cannot be created either
   * because the channel is not supported or there are not enough resources
   * an exception is thrown.</p>
   *
   * @param channeltype
   * @param requestdata
   * @return an open channel
   * @throws ChannelOpenException
   */
  public Ssh2Channel createChannel(String channeltype,
                                   byte[] requestdata) throws
      SshException, ChannelOpenException;
}
