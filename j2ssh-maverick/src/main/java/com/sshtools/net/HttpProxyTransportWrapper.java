/**
 * Copyright 2003-2016 SSHTOOLS Limited. All Rights Reserved.
 *
 * For product documentation visit https://www.sshtools.com/
 *
 * This file is part of J2SSH Maverick.
 *
 * J2SSH Maverick is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * J2SSH Maverick is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with J2SSH Maverick.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.sshtools.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;

import com.sshtools.ssh.SshTransport;

/**
 * Provides an {@link com.sshtools.ssh.SshTransport} implementation that can
 * route the connection through a HTTP proxy.
 * 
 * To connect the transport simply call the {@link connectViaProxy(String, int,
 * String, int, String, String, String)} method. You can pass the name of your
 * application as the user agent and if no authentication is required simply
 * pass ""
 * 
 * @author Lee David Painter
 * 
 */
public class HttpProxyTransportWrapper extends SocketWrapper {
	private String proxyHost;
	private int proxyPort;
	private String remoteHost;
	private int remotePort;
	private HttpResponse responseHeader;
	private String username;
	private String password;
	private String userAgent;

	private static int connectionTimeout = 30000;

	private HttpProxyTransportWrapper(String host, int port, String proxyHost,
			int proxyPort) throws IOException, UnknownHostException {
		super(new Socket());
		this.proxyHost = proxyHost;
		this.proxyPort = proxyPort;
		this.remoteHost = host;
		this.remotePort = port;

		socket.connect(new InetSocketAddress(host, port), connectionTimeout);
		socket.setSoTimeout(connectionTimeout);
	}

	public static void setConnectionTimeout(int connectionTimeout) {
		HttpProxyTransportWrapper.connectionTimeout = connectionTimeout;
	}

	public static int getConnectionTimeout() {
		return connectionTimeout;
	}

	/**
	 * Connect the socket to a HTTP proxy and request forwarding to our remote
	 * host.
	 * 
	 * @param host
	 * @param port
	 * @param proxyHost
	 * @param proxyPort
	 * @param username
	 * @param password
	 * @param userAgent
	 * @return HttpProxyTransportWrapper
	 * @throws IOException
	 * @throws UnknownHostException
	 */
	public static HttpProxyTransportWrapper connectViaProxy(String host,
			int port, String proxyHost, int proxyPort, String username,
			String password, String userAgent) throws IOException,
			UnknownHostException {
		HttpProxyTransportWrapper socket = new HttpProxyTransportWrapper(host,
				port, proxyHost, proxyPort);
		int status;
		socket.username = username;
		socket.password = password;
		socket.userAgent = userAgent;

		try {
			InputStream in = socket.getInputStream();
			OutputStream out = socket.getOutputStream();
			HttpRequest request = new HttpRequest();

			request.setHeaderBegin("CONNECT " + host + ":" + port + " HTTP/1.0");
			request.setHeaderField("User-Agent", userAgent);
			request.setHeaderField("Pragma", "No-Cache");
			request.setHeaderField("Host", host);
			request.setHeaderField("Proxy-Connection", "Keep-Alive");
			out.write(request.toString().getBytes());
			out.flush();
			socket.responseHeader = new HttpResponse(in);

			if (socket.responseHeader.getStatus() == 407) {
				String realm = socket.responseHeader.getAuthenticationRealm();
				String method = socket.responseHeader.getAuthenticationMethod();

				if (realm == null) {
					realm = "";
				}

				if (method.equalsIgnoreCase("basic")) {
					socket.close();
					socket = new HttpProxyTransportWrapper(host, port,
							proxyHost, proxyPort);
					in = socket.getInputStream();
					out = socket.getOutputStream();
					request.setBasicAuthentication(username, password);
					out.write(request.toString().getBytes());
					out.flush();
					socket.responseHeader = new HttpResponse(in);
				} else if (method.equalsIgnoreCase("digest")) {
					throw new IOException(
							"Digest authentication is not supported");
				} else {
					throw new IOException("'" + method + "' is not supported");
				}
			}

			status = socket.responseHeader.getStatus();

		} catch (SocketException e) {
			throw new SocketException("Error communicating with proxy server "
					+ proxyHost + ":" + proxyPort + " (" + e.getMessage() + ")");
		} finally {

		}

		if ((status < 200) || (status > 299)) {
			throw new IOException("Proxy tunnel setup failed: "
					+ socket.responseHeader.getStartLine());
		}

		socket.setSoTimeout(0);
		return socket;
	}

	public String toString() {
		return "HTTPProxySocket [Proxy IP=" + socket.getInetAddress()
				+ ",Proxy Port=" + getPort() + ",localport="
				+ socket.getLocalPort() + "Remote Host=" + remoteHost
				+ "Remote Port=" + String.valueOf(remotePort) + "]";
	}

	HttpHeader getResponseHeader() {
		return responseHeader;
	}

	public String getHost() {
		return remoteHost;
	}

	public SshTransport duplicate() throws IOException {
		return connectViaProxy(remoteHost, remotePort, proxyHost, proxyPort,
				username, password, userAgent);
	}
}
