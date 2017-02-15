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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import com.sshtools.events.Event;
import com.sshtools.events.EventServiceImplementation;
import com.sshtools.events.J2SSHEventCodes;
import com.sshtools.logging.Log;
import com.sshtools.ssh.ChannelAdapter;
import com.sshtools.ssh.Client;
import com.sshtools.ssh.ForwardingRequestListener;
import com.sshtools.ssh.SshChannel;
import com.sshtools.ssh.SshClient;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshTransport;
import com.sshtools.ssh.SshTunnel;
import com.sshtools.ssh.components.ComponentManager;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.IOStreamConnector;

/**
 * <p>
 * Provides management of port forwarding connections and active tunnels.
 * </p>
 * 
 * <p>
 * Three types of forwarding are provided by both SSH protocol versions; local
 * forwarding, remote forwarding, X forwarding.
 * </p>
 * 
 * <p>
 * Local forwarding allows you to transfer data (or socket connections if you
 * prefer) from the local computer to a destination on the remote
 * computer/network. For example you could setup a local forwarding to listen
 * for connection's on port 110 (the POP3 protocol) and forwarding those
 * connections to port 110 at the remote side of the connection. This secures
 * the data by encrypting it within the SSH connection making the insecure POP3
 * protocol secure. It is normally the practice to deliver the connection to a
 * socket on the localhost of the remote computer to ensure that the data is not
 * transmitted over any other insecure network.
 * </p>
 * 
 * <p>
 * Remote forwarding is simply the reverse of this operation; a request is made
 * to the server to listen on a particular port and any connections made are
 * forwarded to the local computer where they are delivered to the required
 * destination.
 * </p>
 * 
 * <p>
 * X forwarding is available for you to forward X11 data from the remote machine
 * to a local X server.
 * </p>
 * 
 * <p>
 * The use of this client is a simple procedure. First create an instance once
 * you have an authenticated <a
 * href="../../maverick/ssh/SshClient.html">SshClient</a>. You can then use the
 * methods to start local forwarding or request remote forwarding. This
 * implementation manages all the connections and manages threads to transfer
 * the data from sockets to the forwarding channels. All you are required to do
 * is to select the forwarding configuration you require. <blockquote>
 * 
 * <pre>
 *  // Create an SshClient instance into the variable ssh
 *  ...
 * 
 *  // Create a forwarding client
 *        ForwardingClient fwd = new ForwardingClient(ssh);
 * 
 *  // Configure X forwarding to deliver to a local X server
 *         fwd.allowX11Forwarding("localhost:0");
 * 
 *  // Request that HTTP requests on the port 8080 be forwarding from the
 *  // remote computer to the local computers HTTP server.
 *        if(!fwd.requestRemoteForwarding("127.0.0.1", 8080, "127.0.0.1", 80)) {
 *                System.out.println("Forwarding request failed!");
 *        }
 * 
 *  // Create a session to start the user's shell (see notes below)
 *        SshSession session = ssh.openSessionChannel();
 *        session.requestPseudoTerminal("vt100",80,24,0,0);
 *        session.startShell();
 * 
 *  // Forwarding POP3 connections made to the local computer to the remote server's POP3 port
 *        fwd.startLocalForwarding("127.0.0.1", 110, "127.0.0.1", 110);
 * 
 *  // Read the output of the users shell until EOF.
 *        InputStream in = session.getInputStream();
 *        try {
 *                int read;
 *                while((read = in.read()) > -1) {
 *                        if(read > 0)
 *                                System.out.print((char)read);
 *                }
 *                } catch(Throwable t) {
 *                        t.printStackTrace();
 *                } finally {
 *                        System.exit(0);
 *                }
 * 
 * </pre>
 * 
 * </blockquote>
 * </p>
 * 
 * <p>
 * The are several restrictions you must follow if you require protocol
 * independence so that your code will work with both SSH1 and SSH2 servers.<br>
 * SSH1 remote forwarding requests MUST be made before you start the users shell
 * and local forwarding's MUST only be started once you have started the users
 * shell. With SSH1 you must always start the user's shell in order to perform
 * port forwarding as this places the protocol into interactive mode.<br>
 * SSH2 does not place any restrictions as to when a remote forwarding is
 * requesting or local forwarding started.
 * </p>
 * 
 * <p>
 * Additionally the single threaded nature of the API means there is no
 * background thread available to service remote forwarding connection requests.
 * In order that these requests are dealt with in a timely fashion you can
 * either ensure that:<br>
 * Your implementation will be required to start the users shell and read from
 * its InputStream until it reaches EOF. This provides a thread to service the
 * incoming requests and conforms to the requirements of using SSH1 forwarding
 * so we recommend you follow this procedure even if you only require SSH2
 * connections.<br>
 * Alternatively you can create a background thread by passing true into the
 * SshConnector.connect method for the buffered parameter.
 * </p>
 * 
 * <p>
 * The X forwarding managed by this class should be requested before starting
 * any sessions. When X forwarding is requested a fake MIT-MAGIC-COOKIE is
 * supplied to the remote machine which protects your real authentication
 * cookies from being detected. When an X11 request comes in the fake cookie is
 * replaced with your real cookie by looking at your .Xauthority file. If in the
 * event that a real cookie cannot be found there are additional methods to
 * either specify an alternative path to your .Xauthority file or to specify the
 * cookie itself. Please note that X forwarding provided by this class does not
 * operate over Unix Domain sockets so you should ensure that your X server is
 * listening on a TCP port.
 * </p>
 * 
 * @author Lee David Painter
 */
public class ForwardingClient implements Client {

	SshClient ssh;

	protected Hashtable<String, Vector<ActiveTunnel>> incomingtunnels = new Hashtable<String, Vector<ActiveTunnel>>();
	protected Hashtable<String, String> remoteforwardings = new Hashtable<String, String>();
	protected Hashtable<String, Vector<ActiveTunnel>> outgoingtunnels = new Hashtable<String, Vector<ActiveTunnel>>();
	protected Hashtable<String, SocketListener> socketlisteners = new Hashtable<String, SocketListener>();
	protected Vector<ForwardingClientListener> clientlisteners = new Vector<ForwardingClientListener>();

	ForwardingListener forwardinglistener = new ForwardingListener();
	TunnelListener tunnellistener = new TunnelListener();
	boolean isXForwarding = false;

	/** The key used to identify X11 forwarding **/
	public static final String X11_KEY = "X11";
	/** The lowest possible random port to select * */
	public final int LOWEST_RANDOM_PORT = 49152;
	/** The highest possible random port to select * */
	public final int HIGHEST_RANDOM_PORT = 65535;

	/**
	 * Create an forwarding client.
	 */
	public ForwardingClient(SshClient ssh) {
		this.ssh = ssh;
	}

	/**
	 * Add a {@link ForwardingClientListener} to receive forwarding events.
	 * 
	 * @param listener
	 *            listener
	 */
	public void addListener(ForwardingClientListener listener) {
		if (listener != null) {
			clientlisteners.addElement(listener);

			SocketListener s;
			Enumeration<SocketListener> en = socketlisteners.elements();
			while (en.hasMoreElements()) {
				s = (SocketListener) en.nextElement();
				if (s.isListening()) {
					listener.forwardingStarted(
							ForwardingClientListener.LOCAL_FORWARDING,
							generateKey(s.addressToBind, s.portToBind),
							s.hostToConnect, s.portToConnect);

				}
			}
			if (Log.isDebugEnabled()) {
				Log.debug(this, "enumerated socketlisteners");
			}

			Enumeration<String> en2 = incomingtunnels.keys();
			String key;
			String destination;
			String hostToConnect;
			int portToConnect;
			while (en2.hasMoreElements()) {
				key = en2.nextElement();
				if (key.equals(X11_KEY)
						|| ssh.getContext().getX11Display() != null
						&& ssh.getContext().getX11Display().equals(key))
					continue;
				destination = (String) remoteforwardings.get(key);
				hostToConnect = destination.substring(0,
						destination.indexOf(':'));
				portToConnect = Integer.parseInt(destination
						.substring(destination.indexOf(':') + 1));

				listener.forwardingStarted(
						ForwardingClientListener.REMOTE_FORWARDING, key,
						hostToConnect, portToConnect);

			}
			if (Log.isDebugEnabled()) {
				Log.debug(this, "enumerated incomingtunnels");
			}

			String display = ssh.getContext().getX11Display();

			if (Log.isDebugEnabled()) {
				Log.debug(this, "display is " + display);
			}

			if (display != null && isXForwarding) {
				String hostname = "localhost";
				int screen;
				int idx = display.indexOf(':');
				if (idx != -1) {
					hostname = display.substring(0, idx);
					screen = Integer.parseInt(display.substring(idx + 1));
				} else {
					screen = Integer.parseInt(display);
				}

				listener.forwardingStarted(
						ForwardingClientListener.X11_FORWARDING, X11_KEY,
						hostname, screen);
			}
		}
	}

	public boolean hasRemoteForwarding(String addressBound, int portBound) {
		return remoteforwardings.containsKey(generateKey(addressBound,
				portBound));
	}

	public boolean hasLocalForwarding(String addressBound, int portBound) {
		return socketlisteners
				.containsKey(generateKey(addressBound, portBound));
	}

	/**
	 * Remove a {@link ForwardingClientListener} from the list receiving
	 * forwarding events.
	 * 
	 * @param listener
	 *            listener
	 */
	public void removeListener(ForwardingClientListener listener) {
		clientlisteners.removeElement(listener);
	}

	/**
	 * Start's a local listening socket and forwards any connections made to the
	 * to the remote side.
	 * 
	 * @param addressToBind
	 *            the listening address
	 * @param portToBind
	 *            the listening port
	 * @param hostToConnect
	 *            the host to connect on the remote side
	 * @param portToConnect
	 *            the port to connect on the remote side
	 * @throws IOException
	 */
	public void startLocalForwarding(String addressToBind, int portToBind,
			String hostToConnect, int portToConnect) throws SshException {
		String key = generateKey(addressToBind, portToBind);

		SocketListener listener = new SocketListener(addressToBind, portToBind,
				hostToConnect, portToConnect);

		listener.start();

		socketlisteners.put(key, listener);

		if (!outgoingtunnels.containsKey(key)) {
			outgoingtunnels.put(key, new Vector<ActiveTunnel>());
		}

		for (int i = 0; i < clientlisteners.size(); i++) {
			((ForwardingClientListener) clientlisteners.elementAt(i))
					.forwardingStarted(
							ForwardingClientListener.LOCAL_FORWARDING, key,
							hostToConnect, portToConnect);
		}
		EventServiceImplementation
				.getInstance()
				.fireEvent(
						(new Event(this,
								J2SSHEventCodes.EVENT_FORWARDING_LOCAL_STARTED,
								true))
								.addAttribute(
										J2SSHEventCodes.ATTRIBUTE_FORWARDING_TUNNEL_ENTRANCE,
										key)
								.addAttribute(
										J2SSHEventCodes.ATTRIBUTE_FORWARDING_TUNNEL_EXIT,
										hostToConnect + ":" + portToConnect));
	}

	/**
	 * Start's a local listening socket and forwards any connections made to the
	 * to the remote side.
	 * 
	 * @param addressToBind
	 *            the listening address
	 * @param maxFailedPorts
	 *            the number of times to retry if the randomly selected port is
	 *            in use.
	 * @param hostToConnect
	 *            the host to connect on the remote side
	 * @param portToConnect
	 *            the port to connect on the remote side
	 * @return the random port on which the tunnel is now listening
	 * @throws IOException
	 */
	public int startLocalForwardingOnRandomPort(String addressToBind,
			int maxFailedPorts, String hostToConnect, int portToConnect)
			throws SshException {

		for (int x = 0; x < maxFailedPorts; x++) {

			try {
				int portToBind = selectRandomPort();

				String key = generateKey(addressToBind, portToBind);

				SocketListener listener = new SocketListener(addressToBind,
						portToBind, hostToConnect, portToConnect);

				listener.start();

				socketlisteners.put(key, listener);

				if (!outgoingtunnels.containsKey(key)) {
					outgoingtunnels.put(key, new Vector<ActiveTunnel>());
				}

				for (int i = 0; i < clientlisteners.size(); i++) {
					((ForwardingClientListener) clientlisteners.elementAt(i))
							.forwardingStarted(
									ForwardingClientListener.LOCAL_FORWARDING,
									key, hostToConnect, portToConnect);
				}

				EventServiceImplementation
						.getInstance()
						.fireEvent(
								(new Event(
										this,
										J2SSHEventCodes.EVENT_FORWARDING_LOCAL_STARTED,
										true))
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_FORWARDING_TUNNEL_ENTRANCE,
												key)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_FORWARDING_TUNNEL_EXIT,
												hostToConnect + ":"
														+ portToConnect));
				return portToBind;

			} catch (Throwable ex) {
			}
		}

		throw new SshException(
				"Maximum retry limit reached for random port selection",
				SshException.FORWARDING_ERROR);
	}

	/**
	 * Returns the currently active remote forwarding listeners.
	 * 
	 * @return String[]
	 */
	public String[] getRemoteForwardings() {
		String[] r = new String[remoteforwardings.size()
				- (remoteforwardings.containsKey(X11_KEY) ? 1 : 0)];
		int index = 0;

		for (Enumeration<String> e = remoteforwardings.keys(); e
				.hasMoreElements();) {
			String key = e.nextElement();
			if (!key.equals(X11_KEY))
				r[index++] = key;
		}
		return r;
	}

	/**
	 * Return the currently active local forwarding listeners.
	 * 
	 * @return String[]
	 */
	public String[] getLocalForwardings() {
		String[] r = new String[socketlisteners.size()];
		int index = 0;

		for (Enumeration<String> e = socketlisteners.keys(); e
				.hasMoreElements();) {
			r[index++] = e.nextElement();

		}
		return r;
	}

	/**
	 * Get the active tunnels for a local forwarding listener.
	 * 
	 * @param key
	 * @return ActiveTunnel[]
	 * @throws IOException
	 */
	public ActiveTunnel[] getLocalForwardingTunnels(String key)
			throws IOException {

		if (outgoingtunnels.containsKey(key)) {
			Vector<ActiveTunnel> v = outgoingtunnels.get(key);
			ActiveTunnel[] t = new ActiveTunnel[v.size()];
			v.copyInto(t);
			return t;
		}

		if (!socketlisteners.containsKey(key)) {
			throw new IOException(key
					+ " is not a valid local forwarding configuration");
		}

		return new ActiveTunnel[] {};
	}

	/**
	 * Get the active tunnels for a local forwarding listener.
	 * 
	 * @param addressToBind
	 * @param portToBind
	 * @return ActiveTunnel[]
	 * @throws IOException
	 */
	public ActiveTunnel[] getLocalForwardingTunnels(String addressToBind,
			int portToBind) throws IOException {
		return getLocalForwardingTunnels(generateKey(addressToBind, portToBind));
	}

	/**
	 * Get all the active remote forwarding tunnels
	 * 
	 * @return
	 * @throws IOException
	 */
	public ActiveTunnel[] getRemoteForwardingTunnels() throws IOException {
		Vector<ActiveTunnel> v = new Vector<ActiveTunnel>();
		String[] remoteForwardings = getRemoteForwardings();
		for (int i = 0; i < remoteForwardings.length; i++) {
			ActiveTunnel[] tmp = getRemoteForwardingTunnels(remoteForwardings[i]);
			for (int x = 0; x < tmp.length; x++) {
				v.add(tmp[x]);
			}
		}

		return (ActiveTunnel[]) v.toArray(new ActiveTunnel[v.size()]);
	}

	/**
	 * Get all the active local forwarding tunnels
	 * 
	 * @return
	 * @throws IOException
	 */
	public ActiveTunnel[] getLocalForwardingTunnels() throws IOException {
		Vector<ActiveTunnel> v = new Vector<ActiveTunnel>();
		String[] localForwardings = getLocalForwardings();
		for (int i = 0; i < localForwardings.length; i++) {
			ActiveTunnel[] tmp = getLocalForwardingTunnels(localForwardings[i]);
			for (int x = 0; x < tmp.length; x++) {
				v.add(tmp[x]);
			}
		}

		return (ActiveTunnel[]) v.toArray(new ActiveTunnel[v.size()]);
	}

	/**
	 * Get the active tunnels for a remote forwarding listener.
	 * 
	 * @param key
	 * @return ActiveTunnel[]
	 * @throws IOException
	 */
	public ActiveTunnel[] getRemoteForwardingTunnels(String key)
			throws IOException {

		synchronized (incomingtunnels) {
			if (incomingtunnels.containsKey(key)) {
				Vector<ActiveTunnel> v = incomingtunnels.get(key);
				ActiveTunnel[] t = new ActiveTunnel[v.size()];
				v.copyInto(t);

				return t;
			}
		}

		if (!remoteforwardings.containsKey(key)) {
			throw new IOException(key
					+ " is not a valid remote forwarding configuration");
		}

		return new ActiveTunnel[] {};
	}

	/**
	 * Is X forwarding currently active?
	 * 
	 * @return boolean
	 */
	public boolean isXForwarding() {
		return isXForwarding;
	}

	/**
	 * Get the active tunnels for a remote forwarding listener.
	 * 
	 * @param addressToBind
	 * @param portToBind
	 * @return ActiveTunnel[]
	 * @throws IOException
	 */
	public ActiveTunnel[] getRemoteForwardingTunnels(String addressToBind,
			int portToBind) throws IOException {
		return getRemoteForwardingTunnels(generateKey(addressToBind, portToBind));
	}

	/**
	 * Get the active X11 forwarding channels.
	 * 
	 * @return ActiveTunnel[]
	 * @throws IOException
	 */
	public ActiveTunnel[] getX11ForwardingTunnels() throws IOException {
		if (incomingtunnels.containsKey(X11_KEY)) {
			Vector<ActiveTunnel> v = incomingtunnels.get(X11_KEY);
			ActiveTunnel[] t = new ActiveTunnel[v.size()];
			v.copyInto(t);

			return t;
		}
		return new ActiveTunnel[] {};
	}

	/**
	 * Requests that the remote side start listening for socket connections so
	 * that they may be forwarded to to the local destination.
	 * 
	 * @param addressToBind
	 *            the listening address on the remote server
	 * @param portToBind
	 *            the listening port on the remote server
	 * @param hostToConnect
	 *            the host to connect on the local side
	 * @param portToConnect
	 *            the port to connect on the local side
	 * @return boolean
	 * @throws IOException
	 */
	public boolean requestRemoteForwarding(String addressToBind,
			int portToBind, String hostToConnect, int portToConnect)
			throws SshException {
		if (ssh.requestRemoteForwarding(addressToBind, portToBind,
				hostToConnect, portToConnect, forwardinglistener)) {
			String key = generateKey(addressToBind, portToBind);
			if (!incomingtunnels.containsKey(key)) {
				incomingtunnels.put(key, new Vector<ActiveTunnel>());
			}
			remoteforwardings.put(key, hostToConnect + ":" + portToConnect);

			for (int i = 0; i < clientlisteners.size(); i++) {
				((ForwardingClientListener) clientlisteners.elementAt(i))
						.forwardingStarted(
								ForwardingClientListener.REMOTE_FORWARDING,
								key, hostToConnect, portToConnect);
			}

			return true;
		}
		return false;
	}

	/**
	 * Configure the forwarding client to manage X11 connections. This method
	 * will configure the {@link com.sshtools.ssh.SshClient} for X11 forwarding
	 * and will generate a fake cookie which will be used to spoof incoming X11
	 * requests. When a request is received the fake cookie will be replaced in
	 * the authentication packet by a real cookie provided and passed onto the X
	 * server.
	 * 
	 * @param display
	 *            String
	 * @param magicCookie
	 *            String
	 * @throws IOException
	 */
	public void allowX11Forwarding(String display, String magicCookie)
			throws SshException {
		if (remoteforwardings.containsKey(X11_KEY))
			throw new SshException("X11 forwarding is already in use!",
					SshException.FORWARDING_ERROR);

		if (!incomingtunnels.containsKey(X11_KEY)) {
			incomingtunnels.put(X11_KEY, new Vector<ActiveTunnel>());
		}

		ssh.getContext().setX11Display(display);
		ssh.getContext().setX11RequestListener(forwardinglistener);

		byte[] cookie = new byte[16];
		if (magicCookie.length() != 32)
			throw new SshException("Invalid MIT-MAGIC_COOKIE-1 value "
					+ magicCookie, SshException.FORWARDING_ERROR);
		for (int i = 0; i < 32; i += 2) {
			cookie[i / 2] = (byte) Integer.parseInt(
					magicCookie.substring(i, i + 2), 16);
		}
		ssh.getContext().setX11RealCookie(cookie);

		String hostname = "localhost";
		int screen = 0;

		int idx = display.indexOf(':');
		if (idx != -1) {
			hostname = display.substring(0, idx);
			display = display.substring(idx + 1);
		}

		if ((idx = display.indexOf('.')) > -1) {
			screen = Integer.parseInt(display.substring(idx + 1));
		}

		for (int i = 0; i < clientlisteners.size(); i++) {
			((ForwardingClientListener) clientlisteners.elementAt(i))
					.forwardingStarted(ForwardingClientListener.X11_FORWARDING,
							X11_KEY, hostname, screen);
		}

		isXForwarding = true;

	}

	/**
	 * Configure the forwarding client to manage X11 connections. This method
	 * will configure the {@link com.sshtools.ssh.SshClient} for X11 forwarding
	 * and will generate a fake cookie which will be used to spoof incoming X11
	 * requests. When a request is received the fake cookie will be replaced in
	 * the authentication packet by a real cookie which is extracted from the
	 * users .Xauthority file.
	 * 
	 * @param display
	 *            String
	 * @throws IOException
	 */
	public void allowX11Forwarding(String display) throws SshException {
		String homeDir = "";
		try {
			homeDir = System.getProperty("user.home");
		} catch (SecurityException e) {
			// ignore
		}
		allowX11Forwarding(display, new File(homeDir, ".Xauthority"));
	}

	/**
	 * Configure the forwarding client to manage X11 connections. This method
	 * will configure the {@link com.sshtools.ssh.SshClient} for X11 forwarding
	 * and will generate a fake cookie which will be used to spoof incoming X11
	 * requests. When a request is received the fake cookie will be replaced in
	 * the authentication packet by a real cookie which is extracted from the
	 * .Xauthority file provided in the File parameter.
	 * 
	 * @param display
	 *            String
	 * @throws IOException
	 */
	public void allowX11Forwarding(String display, File f) throws SshException {

		if (remoteforwardings.containsKey(X11_KEY))
			throw new SshException("X11 forwarding is already in use!",
					SshException.FORWARDING_ERROR);

		if (!incomingtunnels.containsKey(X11_KEY)) {
			incomingtunnels.put(X11_KEY, new Vector<ActiveTunnel>());
		}
		ssh.getContext().setX11Display(display);
		ssh.getContext().setX11RequestListener(forwardinglistener);

		try {

			// Find the users real cookie
			if (f.exists()) {

				String hostname = "";
				int screen = 0;

				int idx = display.indexOf(':');

				if (idx != -1) {
					hostname = display.substring(0, idx);
					screen = Integer.parseInt(display.substring(idx + 1));
				}

				FileInputStream in = new FileInputStream(f);
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				int read;
				while ((read = in.read()) != -1)
					out.write(read);

				in.close();

				byte[] tmp = out.toByteArray();

				ByteArrayReader bar = new ByteArrayReader(tmp);

				try {
					while (bar.available() > 0) {

						short family = bar.readShort();
						short len = bar.readShort();
						byte[] address = new byte[len];
						bar.read(address);

						len = bar.readShort();
						byte[] number = new byte[len];
						bar.read(number);

						len = bar.readShort();
						byte[] name = new byte[len];
						bar.read(name);

						len = bar.readShort();
						byte[] data = new byte[len];
						bar.read(data);

						String n = new String(number);
						int d = Integer.parseInt(n);

						String protocol = new String(name);
						if (protocol.equals("MIT-MAGIC-COOKIE-1")) {
							if (family == 0) {
								// We cannot use InetAddress.getByAddress since
								// it
								// was only introduced in 1.4 :(
								// So we're going to do this really crude
								// formating
								// of the IP Address and get by name
								// which works just as well!
								String ip = (address[0] & 0xFF) + "."
										+ (address[1] & 0xFF) + "."
										+ (address[2] & 0xFF) + "."
										+ (address[3] & 0xFF);
								InetAddress addr = java.net.InetAddress
										.getByName(ip);
								if (addr.getHostAddress().equals(hostname)
										|| addr.getHostName().equals(hostname)) {
									if (screen == d) {
										ssh.getContext().setX11RealCookie(data);
										break;
									}
								}
							} else if (family == 256) {
								String h = new String(address);
								if (h.equals(hostname)) {
									if (screen == d) {
										ssh.getContext().setX11RealCookie(data);
										break;
									}
								}
							}
						}
					}
				} finally {
					bar.close();
				}
			}
			String hostname = "localhost";
			int screen = 0;

			int idx = display.indexOf(':');
			if (idx != -1) {
				hostname = display.substring(0, idx);
				display = display.substring(idx + 1);
			}

			if ((idx = display.indexOf('.')) > -1) {
				screen = Integer.parseInt(display.substring(idx + 1));
			}

			for (int i = 0; i < clientlisteners.size(); i++) {
				((ForwardingClientListener) clientlisteners.elementAt(i))
						.forwardingStarted(
								ForwardingClientListener.X11_FORWARDING,
								X11_KEY, hostname, screen);
			}

			isXForwarding = true;
		} catch (IOException ioe) {
			throw new SshException(ioe.getMessage(),
					SshException.FORWARDING_ERROR);
		}

	}

	/**
	 * Requests that the remote side stop listening for socket connections.
	 * Please note that this feature is not available on SSH1 connections. The
	 * only way to stop the server from listening is to disconnect the
	 * connection.
	 * 
	 * @param bindAddress
	 *            the listening address on the remote side
	 * @param bindPort
	 *            the listening port on the remote side
	 * @throws IOException
	 */
	public void cancelRemoteForwarding(String bindAddress, int bindPort)
			throws SshException {
		cancelRemoteForwarding(bindAddress, bindPort, false);
	}

	/**
	 * Requests that the remote side stop listening for socket connections.
	 * Please note that this feature is not available on SSH1 connections. The
	 * only way to stop the server from listening is to disconnect the
	 * connection.
	 * 
	 * @param bindAddress
	 *            the listening address on the remote side
	 * @param bindPort
	 *            the listening port on the remote side
	 * @param killActiveTunnels
	 *            should any active tunnels be closed
	 * @throws IOException
	 */
	public void cancelRemoteForwarding(String bindAddress, int bindPort,
			boolean killActiveTunnels) throws SshException {

		String key = generateKey(bindAddress, bindPort);
		boolean killedTunnels = false;

		if (killActiveTunnels) {
			try {
				ActiveTunnel[] tunnels = getRemoteForwardingTunnels(
						bindAddress, bindPort);

				if (tunnels != null) {
					for (int i = 0; i < tunnels.length; i++) {
						killedTunnels = true;
						tunnels[i].stop();
					}
				}
			} catch (IOException ex) {
			}
			incomingtunnels.remove(key);
		}

		if (!remoteforwardings.containsKey(key)) {
			if (killActiveTunnels && killedTunnels) {
				return;
			}
			throw new SshException("Remote forwarding has not been started on "
					+ key, SshException.FORWARDING_ERROR);
		}
		// Check to see whether this is local or remote
		if (ssh == null)
			return;

		ssh.cancelRemoteForwarding(bindAddress, bindPort);

		String destination = (String) remoteforwardings.get(key);

		int idx = destination.indexOf(":");

		String hostToConnect;
		int portToConnect;

		if (idx == -1) {
			throw new SshException(
					"Invalid port reference in remote forwarding key!",
					SshException.INTERNAL_ERROR);
		}

		hostToConnect = destination.substring(0, idx);
		portToConnect = Integer.parseInt(destination.substring(idx + 1));

		for (int i = 0; i < clientlisteners.size(); i++) {
			if (clientlisteners.elementAt(i) != null) {
				((ForwardingClientListener) clientlisteners.elementAt(i))
						.forwardingStopped(
								ForwardingClientListener.REMOTE_FORWARDING,
								key, hostToConnect, portToConnect);
			}
		}

		remoteforwardings.remove(key);

	}

	/**
	 * Stop all remote forwarding
	 * 
	 * @throws SshException
	 */
	public synchronized void cancelAllRemoteForwarding() throws SshException {
		cancelAllRemoteForwarding(false);
	}

	/**
	 * Stop all remote forwarding.
	 * 
	 * @param killActiveTunnels
	 *            Should any active tunnels be closed.
	 * @throws SshException
	 */
	public synchronized void cancelAllRemoteForwarding(boolean killActiveTunnels)
			throws SshException {

		if (remoteforwardings == null) {
			return;
		}

		for (Enumeration<String> e = remoteforwardings.keys(); e
				.hasMoreElements();) {
			String host = (String) e.nextElement();

			if (host == null)
				return;

			try {
				int idx = host.indexOf(':');
				int port = -1;
				if (idx == -1) {
					port = Integer.parseInt(host);
					host = "";
				} else {
					port = Integer.parseInt(host.substring(idx + 1));
					host = host.substring(0, idx);
				}
				cancelRemoteForwarding(host, port, killActiveTunnels);
			} catch (NumberFormatException nfe) {

			}
		}
	}

	/**
	 * Select a random port. NOTE: this method does not guarantee that the port
	 * is available.
	 * 
	 * Simply generates a random number in the range LOWEST_RANDOM_PORT to
	 * HIGHEST_RANDOM_PORT
	 * 
	 * @return int
	 */
	protected int selectRandomPort() {

		try {
			int n = HIGHEST_RANDOM_PORT - LOWEST_RANDOM_PORT + 1;
			int i = ComponentManager.getInstance().getRND().nextInt() % n;
			if (i < 0)
				i = -i;
			return LOWEST_RANDOM_PORT + i;
		} catch (SshException e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	/**
	 * Stop all local forwarding
	 */
	public synchronized void stopAllLocalForwarding() throws SshException {
		stopAllLocalForwarding(false);
	}

	/**
	 * Stop all local forwarding
	 * 
	 * @param killActiveTunnels
	 *            should any active tunnels be closed
	 */
	public synchronized void stopAllLocalForwarding(boolean killActiveTunnels)
			throws SshException {
		for (Enumeration<String> e = socketlisteners.keys(); e
				.hasMoreElements();) {
			stopLocalForwarding((String) e.nextElement(), killActiveTunnels);
		}
	}

	/**
	 * Stops a local listening socket from accepting connections.
	 * 
	 * @param bindAddress
	 *            the listening address
	 * @param bindPort
	 *            the listening port
	 */
	public synchronized void stopLocalForwarding(String bindAddress,
			int bindPort) throws SshException {
		stopLocalForwarding(bindAddress, bindPort, false);
	}

	/**
	 * Stops a local listening socket from accepting connections.
	 * 
	 * @param bindAddress
	 *            the listening address
	 * @param bindPort
	 *            the listening port
	 * @param killActiveTunnels
	 *            should any active tunnels be closed.
	 */
	public synchronized void stopLocalForwarding(String bindAddress,
			int bindPort, boolean killActiveTunnels) throws SshException {
		String key = generateKey(bindAddress, bindPort);
		stopLocalForwarding(key, killActiveTunnels);
	}

	/**
	 * Stop a local listening socket from accepting connections.
	 * 
	 * @param key
	 *            the bound address and port in the format "127.0.0.1:8080"
	 * @param killActiveTunnels
	 *            should any active tunnels be closed.
	 * @throws SshException
	 */
	public synchronized void stopLocalForwarding(String key,
			boolean killActiveTunnels) throws SshException {

		if (key == null)
			return;

		boolean killedTunnels = false;

		if (killActiveTunnels) {
			try {
				ActiveTunnel[] tunnels = getLocalForwardingTunnels(key);

				if (tunnels != null) {
					for (int i = 0; i < tunnels.length; i++) {
						tunnels[i].stop();
						killedTunnels = true;
					}
				}
			} catch (IOException ex) {
			}
			outgoingtunnels.remove(key);
		}

		if (!socketlisteners.containsKey(key)) {
			if (killActiveTunnels && killedTunnels) {
				return;
			}
			throw new SshException("Local forwarding has not been started for "
					+ key, SshException.FORWARDING_ERROR);
		}
		// Stop the ServerSocket
		SocketListener listener = (SocketListener) socketlisteners.get(key);

		listener.stop();

		// Remove the listener
		socketlisteners.remove(key);

		for (int i = 0; i < clientlisteners.size(); i++) {
			if (clientlisteners.elementAt(i) != null) {
				((ForwardingClientListener) clientlisteners.elementAt(i))
						.forwardingStopped(
								ForwardingClientListener.LOCAL_FORWARDING, key,
								listener.hostToConnect, listener.portToConnect);
			}
		}
		EventServiceImplementation
				.getInstance()
				.fireEvent(
						(new Event(this,
								J2SSHEventCodes.EVENT_FORWARDING_LOCAL_STOPPED,
								true))
								.addAttribute(
										J2SSHEventCodes.ATTRIBUTE_FORWARDING_TUNNEL_ENTRANCE,
										key)
								.addAttribute(
										J2SSHEventCodes.ATTRIBUTE_FORWARDING_TUNNEL_EXIT,
										listener.hostToConnect + ":"
												+ listener.portToConnect));

	}

	String generateKey(String host, int port) {
		return host.equals("") ? String.valueOf(port) : (host + ":" + String
				.valueOf(port));
	}

	protected class ForwardingListener implements ForwardingRequestListener {

		public SshTransport createConnection(String hostToConnect,
				int portToConnect) throws SshException {
			try {
				SocketTransport t = new SocketTransport(hostToConnect,
						portToConnect);
				t.setSoTimeout(30000);
				return t;
			} catch (IOException ex) {

				for (int i = 0; i < clientlisteners.size(); i++) {
					((ForwardingClientListener) clientlisteners.elementAt(i))
							.channelFailure(
									ForwardingClientListener.REMOTE_FORWARDING,
									hostToConnect + ":" + portToConnect,
									hostToConnect, portToConnect,
									ssh.isConnected(), ex);
				}

				throw new SshException("Failed to connect",
						SshException.CONNECT_FAILED);
			}
		}

		public void initializeTunnel(SshTunnel tunnel) {
			tunnel.addChannelEventListener(tunnellistener);
		}
	}

	class TunnelListener extends ChannelAdapter {
		public void channelOpened(SshChannel channel) {
			if (channel instanceof SshTunnel) {
				ActiveTunnel t = new ActiveTunnel((SshTunnel) channel);

				try {
					t.start();
				} catch (IOException ex) {
				}
			}
		}
	}

	/**
	 * This class represents an active tunnel.
	 * 
	 * @author Lee David Painter
	 */
	public class ActiveTunnel {
		SshTunnel channel;
		IOStreamConnector tx;
		IOStreamConnector rx;

		IOStreamListener listener = new IOStreamListener();

		ActiveTunnel(SshTunnel channel) {
			this.channel = channel;
		}

		SshTunnel getChannel() {
			return channel;
		}

		void start() throws IOException {
			try {

				for (int i = 0; i < clientlisteners.size(); i++) {
					((ForwardingClientListener) clientlisteners.elementAt(i))
							.channelOpened(
									channel.isLocal() ? ForwardingClientListener.LOCAL_FORWARDING
											: channel.isX11() ? ForwardingClientListener.X11_FORWARDING
													: ForwardingClientListener.REMOTE_FORWARDING,
									channel.isX11() ? X11_KEY : generateKey(
											channel.getListeningAddress(),
											channel.getListeningPort()),
									channel);
				}

				// glue forwarding channel in to connection to server out
				rx = new IOStreamConnector();
				rx.addListener(listener);
				// rx.setCloseInput(true);
				rx.connect(channel.getInputStream(), channel.getTransport()
						.getOutputStream());

				// glue connection to server in to forwarding channel out
				tx = new IOStreamConnector();
				tx.addListener(listener);
				// tx.setCloseOutput(false);
				tx.connect(channel.getTransport().getInputStream(),
						channel.getOutputStream());

				String key = generateKey(channel.getListeningAddress(),
						channel.getListeningPort());

				Hashtable<String, Vector<ActiveTunnel>> owner = channel
						.isLocal() ? outgoingtunnels : incomingtunnels;

				if (!owner.containsKey(key)) {
					owner.put(key, new Vector<ActiveTunnel>());
				}

				Vector<ActiveTunnel> tunnels = owner.get(key);

				tunnels.addElement(this);
			} catch (Exception ex) {
				Log.error(this, "Exception whilst opening channel", ex);
				try {
					channel.close();
				} catch (Exception e) {

				}
				throw new IOException("The tunnel failed to start: "
						+ ex.getMessage());
			}
		}

		/**
		 * Stop's the tunnel from transferring data, closing the channel and the
		 * attached socket. This is now synchronized to avoid two threads
		 * stopping this at the same time
		 */
		public synchronized void stop() {
			if (!rx.isClosed()) {
				rx.close();
			}

			if (!tx.isClosed()) {
				tx.close();
			}

			String key = generateKey(channel.getListeningAddress(),
					channel.getListeningPort());

			Hashtable<String, Vector<ActiveTunnel>> owner = channel.isLocal() ? outgoingtunnels
					: incomingtunnels;

			Vector<ActiveTunnel> tunnels = owner.get(key);
			if (tunnels != null && tunnels.contains(this)) {
				tunnels.removeElement(this);

				for (int i = 0; i < clientlisteners.size(); i++) {
					((ForwardingClientListener) clientlisteners.elementAt(i))
							.channelClosed(
									channel.isLocal() ? ForwardingClientListener.LOCAL_FORWARDING
											: channel.isX11() ? ForwardingClientListener.X11_FORWARDING
													: ForwardingClientListener.REMOTE_FORWARDING,
									channel.isX11() ? X11_KEY : key, channel);
				}

			}

		}

		class IOStreamListener implements
				IOStreamConnector.IOStreamConnectorListener {
			public synchronized void connectorClosed(IOStreamConnector connector) {
				if (Log.isDebugEnabled()) {
					Log.debug(
							this,
							"Tunnel connector closed id="
									+ channel.getChannelId() + " localEOF="
									+ channel.isLocalEOF() + " remoteEOF="
									+ channel.isRemoteEOF() + " closed="
									+ channel.isClosed());
				}
				if (!channel.isClosed()) {
					try {
						channel.getTransport().close();
					} catch (IOException ex) {
					}

					try {
						channel.close();
					} catch (Exception ex1) {
					}
				}
				stop();
			}

			public void dataTransfered(byte[] buffer, int count) {
			}

			public void connectorTimeout(IOStreamConnector connector) {
				if (Log.isDebugEnabled()) {
					Log.debug(
							this,
							"IO timeout detected in tunnel id="
									+ channel.getChannelId() + " localEOF="
									+ channel.isLocalEOF() + " remoteEOF="
									+ channel.isRemoteEOF() + " closed="
									+ channel.isClosed());
				}

				if (channel.isLocalEOF() || channel.isRemoteEOF()) {
					try {
						channel.close();
					} catch (IOException e) {
					}
				}

			}
		}

	}

	protected class SocketListener implements Runnable {
		String addressToBind;
		int portToBind;
		String hostToConnect;
		int portToConnect;
		ServerSocket server;
		private Thread thread;
		private boolean listening;

		public SocketListener(String addressToBind, int portToBind,
				String hostToConnect, int portToConnect) {
			this.addressToBind = addressToBind;
			this.portToBind = portToBind;
			this.hostToConnect = hostToConnect;
			this.portToConnect = portToConnect;
		}

		public int getLocalPort() {
			return (server == null) ? (-1) : server.getLocalPort();
		}

		public boolean isListening() {
			return listening;
		}

		public void run() {
			try {
				// Socket socket;
				listening = true;

				while (listening && ssh.isConnected()) {
					final Socket socket = server.accept();

					if (!listening || (socket == null)) {
						break;
					}

					Enumeration<ForwardingClientListener> en = clientlisteners
							.elements();
					ForwardingClientListener listener;
					boolean accepted = true;
					while (en.hasMoreElements()) {
						listener = en.nextElement();
						if (!listener.acceptLocalForwarding(
								socket.getRemoteSocketAddress(), hostToConnect,
								portToConnect)) {
							accepted = false;
							try {
								socket.close();
							} catch (Exception e) {
								if (Log.isDebugEnabled()) {
									Log.debug(this,
											"Listener denied local forwarding to "
													+ hostToConnect + ":"
													+ portToConnect);
								}
							}
							break;
						}
					}

					if (!accepted) {
						continue;
					}

					Thread t = new Thread() {

						public void run() {
							try {
								// Open a forwarding channel and bind to the
								// socket
								ssh.openForwardingChannel(hostToConnect,
										portToConnect, addressToBind,
										portToBind, socket.getInetAddress()
												.getHostAddress(), socket
												.getPort(), new SocketWrapper(
												socket), tunnellistener);
								socket.setSoTimeout(30000);
							} catch (Exception ex) {

								Log.error(this,
										"Exception whilst opening channel", ex);

								try {
									socket.close();
								} catch (IOException ioe) {
								} finally {

									for (int i = 0; i < clientlisteners.size(); i++) {
										((ForwardingClientListener) clientlisteners
												.elementAt(i))
												.channelFailure(
														ForwardingClientListener.LOCAL_FORWARDING,
														addressToBind + ":"
																+ portToBind,
														hostToConnect,
														portToConnect,
														ssh.isConnected(), ex);
									}
								}
							}
						}
					};
					t.start();
				}
			} catch (IOException ioe) {
			} finally {
				stop();
				thread = null;
				server = null;
			}
		}

		public String getHostToConnect() {
			return hostToConnect;
		}

		public int getPortToConnect() {
			return portToConnect;
		}

		public boolean isRunning() {
			return (thread != null) && thread.isAlive();
		}

		public void start() throws SshException {
			/* Bind server socket */
			try {
				server = new ServerSocket(portToBind, 1000,
						addressToBind.equals("") ? null
								: InetAddress.getByName(addressToBind));

				/* Create a thread and start it */
				thread = new Thread(this);
				thread.setDaemon(true);
				thread.setName("SocketListener " + addressToBind + ":"
						+ String.valueOf(portToBind));
				thread.start();
			} catch (IOException ioe) {
				throw new SshException("Failed to local forwarding server. ",
						SshException.CHANNEL_FAILURE, ioe);
			}
		}

		public void stop() {
			try {
				/* Close the server socket */
				if (server != null) {
					server.close();
				}
			} catch (IOException ioe) {
			}
			
			listening = false;
		}
	}

	public void exit() throws SshException {
		stopAllLocalForwarding();
		cancelAllRemoteForwarding();
	}
}
