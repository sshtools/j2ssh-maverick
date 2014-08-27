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
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;

import com.sshtools.ssh.SshTransport;

/**
 * Provides an {@link com.sshtools.ssh.SshTransport} implementation that
 * can route the connection through a SOCKS 4 or SOCKS 5 proxy.
 * @author Lee David Painter
 */
public class SocksProxyTransport extends Socket implements SshTransport {

    public static final int SOCKS4 = 0x04;
    public static final int SOCKS5 = 0x05;
    private static final int CONNECT = 0x01;
    private static final int NULL_TERMINATION = 0x00;

    private final static String[] SOCKSV5_ERROR = {
        "Success", "General SOCKS server failure",
        "Connection not allowed by ruleset", "Network unreachable",
        "Host unreachable", "Connection refused", "TTL expired",
        "Command not supported", "Address type not supported"
    };

    private final static String[] SOCKSV4_ERROR = {
        "Request rejected or failed",
        "SOCKS server cannot connect to identd on the client",
        "The client program and identd report different user-ids"
    };

    private String proxyHost;
    private int proxyPort;
    private String remoteHost;
    private int remotePort;
    private int socksVersion;
    private String username;
    private String password;
    private boolean localLookup;
    private String providerDetail;

    private SocksProxyTransport(String remoteHost, int remotePort,
        String proxyHost, int proxyPort, int socksVersion)
        throws IOException, UnknownHostException {
        super(proxyHost, proxyPort);
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        this.remoteHost = remoteHost;
        this.remotePort = remotePort;
        this.socksVersion = socksVersion;
    }

    /**
     * Connect the socket to a SOCKS 4 proxy and request forwarding to
     * our remote host.
     *
     * @param remoteHost
     * @param remotePort
     * @param proxyHost
     * @param proxyPort
     * @param userId
     * @return SocksProxyTransport
     * @throws IOException
     * @throws UnknownHostException
     */
    public static SocksProxyTransport connectViaSocks4Proxy(String remoteHost,
        int remotePort, String proxyHost, int proxyPort, String userId)
        throws IOException, UnknownHostException {
        SocksProxyTransport proxySocket = new SocksProxyTransport(remoteHost,
                remotePort, proxyHost, proxyPort, SOCKS4);
        proxySocket.username = userId;
        try {
            InputStream proxyIn = proxySocket.getInputStream();
            OutputStream proxyOut = proxySocket.getOutputStream();
            InetAddress hostAddr = InetAddress.getByName(remoteHost);
            proxyOut.write(SOCKS4);
            proxyOut.write(CONNECT);
            proxyOut.write((remotePort >>> 8) & 0xff);
            proxyOut.write(remotePort & 0xff);
            proxyOut.write(hostAddr.getAddress());
            proxyOut.write(userId.getBytes());
            proxyOut.write(NULL_TERMINATION);
            proxyOut.flush();

            int res = proxyIn.read();

            if (res == -1) {
                throw new IOException("SOCKS4 server " + proxyHost + ":" +
                    proxyPort + " disconnected");
            }

            if (res != 0x00) {
                throw new IOException("Invalid response from SOCKS4 server (" +
                    res + ") " + proxyHost + ":" + proxyPort);
            }

            int code = proxyIn.read();

            if (code != 90) {
                if ((code > 90) && (code < 93)) {
                    throw new IOException(
                        "SOCKS4 server unable to connect, reason: " +
                        SOCKSV4_ERROR[code - 91]);
                }
				throw new IOException(
				    "SOCKS4 server unable to connect, reason: " + code);
            }

            byte[] data = new byte[6];

            if (proxyIn.read(data, 0, 6) != 6) {
                throw new IOException(
                    "SOCKS4 error reading destination address/port");
            }

            proxySocket.setProviderDetail(data[2] + "." + data[3] + "." +
                data[4] + "." + data[5] + ":" + ((data[0] << 8) | data[1]));
        } catch (SocketException e) {
            throw new SocketException("Error communicating with SOCKS4 server " +
                proxyHost + ":" + proxyPort + ", " + e.getMessage());
        }

        return proxySocket;
    }

    private void setProviderDetail(String providerDetail) {
		this.providerDetail = providerDetail;
	}

	/**
     * Connect the socket to a SOCKS 5 proxy and request forwarding
     * to our remote host.
     * @param remoteHost
     * @param remotePort
     * @param proxyHost
     * @param proxyPort
     * @param localLookup
     * @param username
     * @param password
     * @return SocksProxyTransport
     * @throws IOException
     * @throws UnknownHostException
     */
    public static SocksProxyTransport connectViaSocks5Proxy(String remoteHost,
        int remotePort, String proxyHost, int proxyPort, boolean localLookup,
        String username, String password)
        throws IOException, UnknownHostException {
        SocksProxyTransport proxySocket = new SocksProxyTransport(remoteHost,
                remotePort, proxyHost, proxyPort, SOCKS5);
        proxySocket.username = username;
        proxySocket.password = password;
        proxySocket.localLookup = localLookup;

        try {
            InputStream proxyIn = proxySocket.getInputStream();
            OutputStream proxyOut = proxySocket.getOutputStream();
            byte[] request = {
                (byte) SOCKS5, (byte) 0x02, (byte) 0x00, (byte) 0x02
            };
//            byte[] reply = new byte[2];
            proxyOut.write(request);
            proxyOut.flush();

            int res = proxyIn.read();

            if (res == -1) {
                throw new IOException("SOCKS5 server " + proxyHost + ":" +
                    proxyPort + " disconnected");
            }

            if (res != 0x05) {
                throw new IOException("Invalid response from SOCKS5 server (" +
                    res + ") " + proxyHost + ":" + proxyPort);
            }

            int method = proxyIn.read();

            switch (method) {
            case 0x00:
                break;

            case 0x02:
                performAuthentication(proxyIn, proxyOut, username, password,
                    proxyHost, proxyPort);

                break;

            default:
                throw new IOException(
                    "SOCKS5 server does not support our authentication methods");
            }

            if (localLookup) {
                InetAddress hostAddr;

                try {
                    hostAddr = InetAddress.getByName(remoteHost);
                } catch (UnknownHostException e) {
                    throw new IOException("Can't do local lookup on: " +
                        remoteHost + ", try socks5 without local lookup");
                }

                request = new byte[] {
                        (byte) SOCKS5, (byte) 0x01, (byte) 0x00, (byte) 0x01
                    };
                proxyOut.write(request);
                proxyOut.write(hostAddr.getAddress());
            } else {
                request = new byte[] {
                        (byte) SOCKS5, (byte) 0x01, (byte) 0x00, (byte) 0x03
                    };
                proxyOut.write(request);
                proxyOut.write(remoteHost.length());
                proxyOut.write(remoteHost.getBytes());
            }

            proxyOut.write((remotePort >>> 8) & 0xff);
            proxyOut.write(remotePort & 0xff);
            proxyOut.flush();
            res = proxyIn.read();

            if (res != 0x05) {
                throw new IOException("Invalid response from SOCKS5 server (" +
                    res + ") " + proxyHost + ":" + proxyPort);
            }

            int status = proxyIn.read();

            if (status != 0x00) {
                if ((status > 0) && (status < 9)) {
                    throw new IOException(
                        "SOCKS5 server unable to connect, reason: " +
                        SOCKSV5_ERROR[status]);
                }
				throw new IOException(
				    "SOCKS5 server unable to connect, reason: " + status);
            }

            proxyIn.read();

            int aType = proxyIn.read();
            byte[] data = new byte[255];

            switch (aType) {
            case 0x01:

                if (proxyIn.read(data, 0, 4) != 4) {
                    throw new IOException("SOCKS5 error reading address");
                }

                proxySocket.setProviderDetail(data[0] + "." + data[1] + "." +
                    data[2] + "." + data[3]);

                break;

            case 0x03:

                int n = proxyIn.read();

                if (proxyIn.read(data, 0, n) != n) {
                    throw new IOException("SOCKS5 error reading address");
                }

                proxySocket.setProviderDetail(new String(data));

                break;

            default:
                throw new IOException("SOCKS5 gave unsupported address type: " +
                    aType);
            }

            if (proxyIn.read(data, 0, 2) != 2) {
                throw new IOException("SOCKS5 error reading port");
            }

            proxySocket.setProviderDetail(proxySocket.getProviderDetail() + (":" + ((data[0] << 8) | data[1])));
        } catch (SocketException e) {
            throw new SocketException("Error communicating with SOCKS5 server " +
                proxyHost + ":" + proxyPort + ", " + e.getMessage());
        }

        return proxySocket;
    }

    private String getProviderDetail() {
		return providerDetail;
	}

	private static void performAuthentication(InputStream proxyIn,
        OutputStream proxyOut, String username, String password,
        String proxyHost, int proxyPort) throws IOException {
        proxyOut.write(0x01);
        proxyOut.write(username.length());
        proxyOut.write(username.getBytes());
        proxyOut.write(password.length());
        proxyOut.write(password.getBytes());

        int res = proxyIn.read();

        if ((res != 0x01) && (res != 0x05)) {
            throw new IOException("Invalid response from SOCKS5 server (" +
                res + ") " + proxyHost + ":" + proxyPort);
        }

        if (proxyIn.read() != 0x00) {
            throw new IOException("Invalid username/password for SOCKS5 server");
        }
    }

    public String toString() {
        return "SocksProxySocket[addr=" + getInetAddress() + ",port=" +
        getPort() + ",localport=" + getLocalPort() + "]";
    }

    public static SocksProxyTransport connectViaSocks5Proxy(String remoteHost,
        int remotePort, String proxyHost, int proxyPort, String username,
        String password) throws IOException, UnknownHostException {
        return connectViaSocks5Proxy(remoteHost, remotePort, proxyHost,
            proxyPort, false, username, password);
    }

    public String getHost() {
      return remoteHost;
    }

    public SshTransport duplicate() throws IOException {
      switch(socksVersion) {
        case SOCKS4:
          return connectViaSocks4Proxy(remoteHost,
                                       remotePort,
                                       proxyHost,
                                       proxyPort,
                                       username);

        default:
          return connectViaSocks5Proxy(remoteHost,
                                       remotePort,
                                       proxyHost,
                                       proxyPort,
                                       localLookup,
                                       username,
                                       password);
      }
    }
}
