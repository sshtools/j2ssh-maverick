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
 * You should have received a copy of the GNU General Public License
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
import java.util.Enumeration;
import java.util.Hashtable;

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
 */
public class HttpProxyTransport extends Socket implements SshTransport {
	private String proxyHost;
	private int proxyPort;
	private String remoteHost;
	private int remotePort;
	private HttpResponse responseHeader;
	private String username;
	private String password;
	private String userAgent;
	private HttpRequest request = new HttpRequest();
	private Hashtable<String, String> optionalHeaders;

	private static int connectionTimeout = 30000;

	private HttpProxyTransport(String host, int port, String proxyHost,
			int proxyPort) throws IOException, UnknownHostException {
		this.proxyHost = proxyHost;
		this.proxyPort = proxyPort;
		this.remoteHost = host;
		this.remotePort = port;

		connect(new InetSocketAddress(proxyHost, proxyPort), connectionTimeout);
		setSoTimeout(connectionTimeout);
	}

	public static void setConnectionTimeout(int connectionTimeout) {
		HttpProxyTransport.connectionTimeout = connectionTimeout;
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
	 * @return HttpProxyTransport
	 * @throws IOException
	 * @throws UnknownHostException
	 */
	public static HttpProxyTransport connectViaProxy(String host, int port,
			String proxyHost, int proxyPort, String username, String password,
			String userAgent) throws IOException, UnknownHostException {
		return connectViaProxy(host, port, proxyHost, proxyPort, username,
				password, userAgent, null);
	}

	/**
	 * 
	 * @param host
	 * @param port
	 * @param proxyHost
	 * @param proxyPort
	 * @param username
	 * @param password
	 * @param userAgent
	 * @param optionalHeaders
	 * @return
	 * @throws IOException
	 * @throws UnknownHostException
	 */
	public static HttpProxyTransport connectViaProxy(String host, int port,
			String proxyHost, int proxyPort, String username, String password,
			String userAgent, Hashtable<String, String> optionalHeaders)
			throws IOException, UnknownHostException {
		HttpProxyTransport socket = new HttpProxyTransport(host, port,
				proxyHost, proxyPort);
		int status;
		socket.username = username;
		socket.password = password;
		socket.userAgent = userAgent;
		socket.optionalHeaders = optionalHeaders;

		try {
			InputStream in = socket.getInputStream();
			OutputStream out = socket.getOutputStream();

			socket.request.setHeaderBegin("CONNECT " + host + ":" + port
					+ " HTTP/1.0");
			socket.request.setHeaderField("User-Agent", userAgent);
			socket.request.setHeaderField("Pragma", "No-Cache");
			socket.request.setHeaderField("Host", host);
			socket.request.setHeaderField("Proxy-Connection", "Keep-Alive");

			if (optionalHeaders != null) {
				for (Enumeration<String> e = optionalHeaders.keys(); e
						.hasMoreElements();) {
					String h = e.nextElement();
					socket.request.setHeaderField(h, optionalHeaders.get(h));
				}
			}
			out.write(socket.request.toString().getBytes());
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
					socket = new HttpProxyTransport(host, port, proxyHost,
							proxyPort);
					in = socket.getInputStream();
					out = socket.getOutputStream();
					socket.request.setBasicAuthentication(username, password);
					out.write(socket.request.toString().getBytes());
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
		}

		if ((status < 200) || (status > 299)) {
			throw new IOException("Proxy tunnel setup failed: "
					+ socket.responseHeader.getStartLine());
		}

		socket.setSoTimeout(0);
		return socket;
	}

	public String toString() {
		return "HTTPProxySocket [Proxy IP=" + getInetAddress() + ",Proxy Port="
				+ getPort() + ",localport=" + getLocalPort() + "Remote Host="
				+ remoteHost + "Remote Port=" + String.valueOf(remotePort)
				+ "]";
	}

	HttpHeader getResponseHeader() {
		return responseHeader;
	}

	public String getHost() {
		return remoteHost;
	}

	public SshTransport duplicate() throws IOException {
		return connectViaProxy(remoteHost, remotePort, proxyHost, proxyPort,
				username, password, userAgent, optionalHeaders);
	}
}
