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

package com.sshtools.ssh2;

import java.io.IOException;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshIOException;
import com.sshtools.ssh.SshTransport;
import com.sshtools.ssh.SshTunnel;
import com.sshtools.ssh.message.SshChannelMessage;
/**
 *
 * @author Lee David Painter
 */
class Ssh2ForwardingChannel
    extends Ssh2Channel
    implements SshTunnel {

  public static final String X11_FORWARDING_CHANNEL = "x11";
  public static final String LOCAL_FORWARDING_CHANNEL = "direct-tcpip";
  public static final String REMOTE_FORWARDING_CHANNEL = "forwarded-tcpip";

  protected final static String X11AUTH_PROTO = "MIT-MAGIC-COOKIE-1";
  SshTransport transport;
  String host;
  int port;
  String listeningAddress;
  int listeningPort;
  String originatingHost;
  int originatingPort;

  byte[] buf = new byte[1024];
  boolean hasSpoofedCookie = false;
  int idx = 0;
  int requiredLength = 12; // header len
  int protocolLength;
  int cookieLength;
  /**
   * @param name
   * @param windowsize
   * @param packetsize
   */
  public Ssh2ForwardingChannel(String name,
                               int remotewindow,
                               int remotepacket,
                               String host,
                               int port,
                               String listeningAddress,
                               int listeningPort,
                               String originatingHost,
                               int originatingPort,
                               SshTransport transport) {
    super(name, remotewindow, remotepacket);
    this.transport = transport;
    this.host = host;
    this.port = port;
    this.listeningAddress = listeningAddress;
    this.listeningPort = listeningPort;
    this.originatingHost = originatingHost;
    this.originatingPort = originatingPort;

  }


  public String getHost() {
    return host;
  }

  public String getConnectedHost() {
  return getHost();
}

  public int getPort() {
    return port;
  }

  public String getOriginatingHost() {
    return originatingHost;
  }

  public int getOriginatingPort() {
    return originatingPort;
  }

  public String getListeningAddress() {
    return listeningAddress;
  }

  public int getListeningPort() {
    return listeningPort;
  }

  public boolean isLocal() {
    return getName().equals(Ssh2ForwardingChannel.LOCAL_FORWARDING_CHANNEL);
  }

  public boolean isX11() {
    return getName().equals(Ssh2ForwardingChannel.X11_FORWARDING_CHANNEL);
  }

  public SshTransport getTransport() {
    return transport;
  }
  
  public boolean isLocalEOF() {
	  return isLocalEOF;
  }
  
  public boolean isRemoteEOF() {
	  return isRemoteEOF;
  }

  public SshTransport duplicate() throws IOException {
    throw new SshIOException(new SshException("SSH tunnels cannot be duplicated!",
                                              SshException.BAD_API_USAGE));
  }

  public void close() {

      // DEBUG START
      /*System.out.println(getName()
                         + " id="
                         + channelid
                         + " rid="
                         + remoteid
                         + " CLOSING localwindow="
                         + localwindow.available()
                         + " remotewindow="
                         + remotewindow.available());*/
      // DEBUG END
      super.close();
  }

  protected void processStandardData(int len, SshChannelMessage msg) throws SshException {

	    //System.out.println(getName() + " id=" + channelid + " rid=" + remoteid + " localwindow=" + localwindow.available() + " remotewindow=" + remotewindow.available());

	    if(getName().equals(X11_FORWARDING_CHANNEL)) {
	      if(!hasSpoofedCookie) {
	       int n;

	       if(idx < 12) {
	           n = readMore(msg);
	           len -= n;
	           if(requiredLength == 0) {
	            if(buf[0] == 0x42) {
	                protocolLength  =
	                 ((buf[6] & 0xff) << 8) | (buf[7] & 0xff);
	                cookieLength =
	                 ((buf[8] & 0xff) << 8) | (buf[9] & 0xff);
	            } else if(buf[0] == 0x6c) {
	                protocolLength  =
	                 ((buf[7] & 0xff) << 8) | (buf[6] & 0xff);
	                cookieLength =
	                 ((buf[9] & 0xff) << 8) | (buf[8] & 0xff);
	            } else {
	                close();
	                throw new SshException("Corrupt X11 authentication packet",
	                                       SshException.CHANNEL_FAILURE);
	            }
	            requiredLength  = (protocolLength + 0x03) & ~0x03;
	            requiredLength += (cookieLength + 0x03) & ~0x03;
	            if(requiredLength + idx > buf.length) {
	                close();
	                throw new SshException("Corrupt X11 authentication packet",
	                                       SshException.CHANNEL_FAILURE);
	            }
	            if(requiredLength == 0) {
	                close();
	                throw
	                 new SshException("X11 authentication cookie not found",
	                                  SshException.CHANNEL_FAILURE);
	            }
	           }
	       }

	       // Read payload of authentication packet
	       //
	       if(len > 0) {
	           n = readMore(msg);
	           len -= n;
	           if(requiredLength == 0) {
	            byte[] fakeCookie = connection.getContext().getX11AuthenticationCookie();
	            String protoStr   = new String(buf, 12, protocolLength);
	            byte[] recCookie  = new byte[fakeCookie.length];

	            protocolLength = ((protocolLength + 0x03) & ~0x03);

	            System.arraycopy(buf, 12 + protocolLength,
	                       recCookie, 0, fakeCookie.length);
	            if(!X11AUTH_PROTO.equals(protoStr) ||
	               !compareCookies(fakeCookie, recCookie,
	                         fakeCookie.length)) {
	                close();
	                throw new SshException("Incorrect X11 cookie",
	                                       SshException.CHANNEL_FAILURE);
	            }
	            byte[] realCookie = connection.getContext().getX11RealCookie();
	            if(realCookie.length != cookieLength) {
	                throw new SshException("Invalid X11 cookie",
	                                       SshException.CHANNEL_FAILURE);
	            }
	            System.arraycopy(realCookie, 0, buf, 12 + protocolLength,
	                       realCookie.length);
	            hasSpoofedCookie = true;
	            super.processStandardData(len, msg);
	            buf = null;
	           }
	       }

	       if(!hasSpoofedCookie || len == 0) {
	           return;
	       }
	      }


	    }

	    super.processStandardData(len, msg);

	  }


	  private boolean compareCookies(byte[] src, byte[] dst, int len) {
	      int i = 0;
	      for(; i < len; i++) {
	       if(src[i] != dst[i]) {
	           break;
	       }
	      }
	      return i == len;
	  }

	  private int readMore(SshChannelMessage msg) {
		  int len = msg.available();
	      if(len > requiredLength) {
	    	   msg.read(buf, idx, requiredLength);
		       idx      += requiredLength;
		       len       = requiredLength;
		       requiredLength = 0;
	      } else {
	    	  msg.read(buf, idx, len);
	    	  idx       += len;
	    	  requiredLength -= len;
	      }
	      return len;
	  }



}
