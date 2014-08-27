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

package com.sshtools.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import com.sshtools.ssh.SocketTimeoutSupport;
import com.sshtools.ssh.SshTransport;

/**
 *
 * Implements a basic wrapper around a Socket to provide an
 * <a href="../../maverick/ssh/SshTransport.html">SshTransport</a> suitable
 * for use in making connections using the <a href="../../maverick/ssh/SshConnector.html">SshConnector</a>.
 *
 * @author Lee David Painter
 */
public class SocketWrapper
    implements SshTransport, SocketTimeoutSupport{

  protected Socket socket;

  /**
   * Create a SocketWrapper
   * @param socket
   */
  public SocketWrapper(Socket socket) {
    this.socket = socket;
  }

  public InputStream getInputStream() throws IOException {
    return socket.getInputStream();
  }

  public OutputStream getOutputStream() throws IOException {
    return socket.getOutputStream();
  }

  public String getHost() {
    return socket.getInetAddress() == null ? "proxied" : socket.getInetAddress().getHostAddress();
  }

  public int getPort() {
    return socket.getPort();
  }

  public void close() throws IOException {
    socket.close();
  }

  public SshTransport duplicate() throws IOException {
    return new SocketWrapper(new Socket(getHost(), socket.getPort()));
  }

  public void setSoTimeout(int timeout) throws IOException {
      socket.setSoTimeout(timeout);
  }

  public int getSoTimeout() throws IOException{
      return socket.getSoTimeout();
  }
}
