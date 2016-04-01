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
package com.sshtools.ssh2;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.StringTokenizer;
import java.util.Vector;

import com.sshtools.events.Event;
import com.sshtools.events.EventServiceImplementation;
import com.sshtools.events.J2SSHEventCodes;
import com.sshtools.logging.Log;
import com.sshtools.ssh.SocketTimeoutSupport;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshIOException;
import com.sshtools.ssh.SshTransport;
import com.sshtools.ssh.components.ComponentManager;
import com.sshtools.ssh.components.Digest;
import com.sshtools.ssh.components.SshCipher;
import com.sshtools.ssh.components.SshHmac;
import com.sshtools.ssh.components.SshKeyExchangeClient;
import com.sshtools.ssh.components.SshPublicKey;
import com.sshtools.ssh.compression.SshCompression;
import com.sshtools.ssh.message.SshMessageReader;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;

/**
 * <p>
 * Main implementation of the SSH Transport Protocol. The transport is designed
 * to run over a provider such as a Socket or StreamConnection. To use first
 * create an instance of the protocol and set its parameters and when ready
 * start the protocol using <a
 * href="#startTransportProtocol(TransportProvider)">startTransportProtocol</a>
 * supplying a <a href="TransportProvider.html">TransportProvider</a> instance.
 * This example uses the SocketProvider example implementation demonstrated in
 * <a href="TransportProvider.html">TransportProvider Help File</a>.
 * <blockquote>
 * 
 * <pre>
 * TransportProtocol transport = new TransportProtocol();
 * transport.ignoreHostKeyVerification(true);
 * transport.startTransportProtocol(new SocketProvider(&quot;titan&quot;, 22));
 * </pre>
 * 
 * </blockquote>
 * </p>
 * 
 * <p>
 * Host key verification is recommended and a callback interface is provided by
 * <a href="HostKeyVerification.html">HostKeyVerifcation</a>. To force
 * verification use <a href="#setHostKeyVerification(HostKeyVerification)">
 * setHostKeyVerification()</a> before starting the protocol. This is required
 * by default but can be ignored with <a
 * href="#ignoreHostKeyVerification(boolean)"> ignoreHostKeyVerification(boolean
 * ignore)</a>.
 * </p>
 * 
 * <p>
 * Additional cipher, message authentication and compression components can be
 * supported by providing a custom <a href="TransportContext.html">
 * TransportContext</a>. The default context provides all the required
 * components of the protocol but others can be added by creating an instance
 * and adding the various implementations to the component factories.
 * <blockquote>
 * 
 * <pre>
 * TransportContext context = new TransportContext();
 * context.supportedCiphers().add(&quot;blowfish-cbc&quot;, &quot;com.mycrypt.Blowfish&quot;);
 * 
 * TransportProtocol transport = new TransportProtocol(
 * 		TransportProtocol.CLIENT_MODE, context);
 * </pre>
 * 
 * </blockquote>
 * </p>
 * <p>
 * The context can also be used to specify the preferred methods of encryption
 * for the connection which you may want to use should you add a new method to
 * the context. <blockquote>
 * 
 * <pre>
 * context.setPreferredCipherCS(&quot;blowfish-cbc&quot;);
 * </pre>
 * 
 * </blockquote>
 * </p>
 * 
 * @see TransportProvider
 * @author Lee David Painter
 */
public class TransportProtocol implements SshMessageReader {

	/**
	 * Character set encoding. All input/output strings created by the API are
	 * created with this encoding. The default is "UTF-8" and it may be changed,
	 * the results however are unexpected.
	 */
	public static String CHARSET_ENCODING = "UTF8";

	DataInputStream transportIn;
	OutputStream transportOut;
	SshTransport provider;

	Ssh2Context transportContext;
	Ssh2Client client;

	String localIdentification;
	String remoteIdentification;
	byte[] localkex;
	byte[] remotekex;
	byte[] sessionIdentifier;

	static final int SSH_MSG_DISCONNECT = 1;
	static final int SSH_MSG_IGNORE = 2;
	static final int SSH_MSG_UNIMPLEMENTED = 3;
	static final int SSH_MSG_DEBUG = 4;
	static final int SSH_MSG_SERVICE_REQUEST = 5;
	static final int SSH_MSG_SERVICE_ACCEPT = 6;

	static final int SSH_MSG_KEX_INIT = 20;
	static final int SSH_MSG_NEWKEYS = 21;

	/**
	 * Protocol state: Negotation of the protocol version
	 */
	public final static int NEGOTIATING_PROTOCOL = 1;

	/**
	 * Protocol state: The protocol is performing key exchange
	 */
	public final static int PERFORMING_KEYEXCHANGE = 2;

	/**
	 * Protocol state: The transport protocol is connected and services can be
	 * started or may already be active.
	 */
	public final static int CONNECTED = 3;

	/**
	 * Protocol state: The transport protocol has disconnected.
	 * 
	 * @see #getLastError()
	 */
	public final static int DISCONNECTED = 4;

	int currentState;
	Throwable lastError;
	String disconnectReason;

	SshKeyExchangeClient keyExchange;
	SshKeyExchangeClient guessedKeyExchange;
	SshCipher encryption;
	SshCipher decryption;
	SshHmac outgoingMac;
	SshHmac incomingMac;
	SshCompression outgoingCompression;
	SshCompression incomingCompression;
	SshPublicKey hostkey;
	boolean isIncomingCompressing = false;
	boolean isOutgoingCompressing = false;

	int outgoingCipherLength = 8;
	int outgoingMacLength = 0;

	boolean ignoreHostKeyifEmpty = false;

	byte[] incomingMessage;
	ByteArrayWriter outgoingMessage;

	int incomingCipherLength = 8;
	int incomingMacLength = 0;

	long outgoingSequence = 0;
	long incomingSequence = 0;

	final static int MAX_NUM_PACKETS_BEFORE_REKEY = 2147483647;
	final static int MAX_NUM_BYTES_BEFORE_REKEY = 1073741824;

	int numIncomingBytesSinceKEX;
	int numIncomingPacketsSinceKEX;
	int numOutgoingBytesSinceKEX;
	int numOutgoingPacketsSinceKEX;

	long outgoingBytes = 0;
	long incomingBytes = 0;

	Vector<byte[]> kexqueue = new Vector<byte[]>();
	Vector<Runnable> shutdownHooks = new Vector<Runnable>();
	Vector<TransportProtocolListener> listeners = new Vector<TransportProtocolListener>();

	long lastActivity = System.currentTimeMillis();

	/** Disconnect reason: The host is not allowed */
	public final static int HOST_NOT_ALLOWED = 1;

	/** Disconnect reason: A protocol error occurred */
	public final static int PROTOCOL_ERROR = 2;

	/** Disconnect reason: Key exchange failed */
	public final static int KEY_EXCHANGE_FAILED = 3;

	/** Disconnect reason: Reserved */
	public final static int RESERVED = 4;

	/** Disconnect reason: An error occurred verifying the MAC */
	public final static int MAC_ERROR = 5;

	/** Disconnect reason: A compression error occurred */
	public final static int COMPRESSION_ERROR = 6;

	/** Disconnect reason: The requested service is not available */
	public final static int SERVICE_NOT_AVAILABLE = 7;

	/** Disconnect reason: The protocol version is not supported */
	public final static int PROTOCOL_VERSION_NOT_SUPPORTED = 8;

	/** Disconnect reason: The host key supplied could not be verified */
	public final static int HOST_KEY_NOT_VERIFIABLE = 9;

	/** Disconnect reason: The connection was lost */
	public final static int CONNECTION_LOST = 10;

	/** Disconnect reason: The application disconnected */
	public final static int BY_APPLICATION = 11;

	/** Disconnect reason: Too many connections, try later */
	public final static int TOO_MANY_CONNECTIONS = 12;

	/** Disconnect reason: Authentication was cancelled */
	public final static int AUTH_CANCELLED_BY_USER = 13;

	/** Disconnect reason: No more authentication methods are available */
	public final static int NO_MORE_AUTH_METHODS_AVAILABLE = 14;

	/** Disconnect reason: The user's name is illegal */
	public final static int ILLEGAL_USER_NAME = 15;

	boolean verbose = Boolean.valueOf(
			System.getProperty("maverick.verbose", "false")).booleanValue();

	/**
	 * Create a default transport protocol instance in CLIENT_MODE.
	 * 
	 * @throws IOException
	 */
	public TransportProtocol() {
	}

	public SshTransport getProvider() {
		return provider;
	}

	public void addListener(TransportProtocolListener listener) {
		listeners.addElement(listener);
	}

	/**
	 * Get the SshClient instance that created this transport.
	 * 
	 * @return
	 */
	public Ssh2Client getClient() {
		return client;
	}

	/**
	 * Returns the connected state
	 * 
	 * @return <tt>true</tt> if the transport is connected, otherwise
	 *         <tt>false</tt>
	 */
	public boolean isConnected() {
		return currentState == CONNECTED
				|| currentState == PERFORMING_KEYEXCHANGE;
	}

	/**
	 * Returns the last error detected by the protocol. If a disconnect occurs
	 * this may provide a reason.
	 * 
	 * @return a last error detected by the transport protocol.
	 */
	public Throwable getLastError() {
		return lastError;
	}

	public Ssh2Context getContext() {
		return transportContext;
	}

	public boolean getIgnoreHostKeyifEmpty() {
		return ignoreHostKeyifEmpty;
	}

	public void setIgnoreHostKeyifEmpty(boolean ignoreHostKeyifEmpty) {
		this.ignoreHostKeyifEmpty = ignoreHostKeyifEmpty;
	}

	/**
	 * Starts the protocol on the provider.
	 */
	public void startTransportProtocol(SshTransport provider,
			Ssh2Context context, String localIdentification,
			String remoteIdentification, Ssh2Client client) throws SshException {

		try {
			this.transportIn = new DataInputStream(provider.getInputStream());
			this.transportOut = provider.getOutputStream();
			this.provider = provider;
			this.localIdentification = localIdentification;
			this.remoteIdentification = remoteIdentification;
			this.transportContext = context;
			this.incomingMessage = new byte[transportContext
					.getMaximumPacketLength()];
			this.outgoingMessage = new ByteArrayWriter(
					transportContext.getMaximumPacketLength());
			this.client = client;

			// Negotiate the protocol version
			currentState = TransportProtocol.NEGOTIATING_PROTOCOL;

			// Perform key exchange
			sendKeyExchangeInit(false);

			if (Log.isDebugEnabled()) {
				Log.debug(this,
						"Waiting for transport protocol to complete initialization");
			}

			while (processMessage(readMessage()) && currentState != CONNECTED) {
				;
			}
		} catch (IOException ex) {
			throw new SshException(ex, SshException.CONNECT_FAILED);
		}

		if (Log.isDebugEnabled()) {
			Log.debug(this, "Transport protocol initialized");
		}

	}

	/**
	 * Get the identification string sent by the server during protocol
	 * negotiation
	 * 
	 * @return String
	 */
	public String getRemoteIdentification() {
		return remoteIdentification;
	}

	/**
	 * Get the session identifier
	 * 
	 * @return byte[]
	 */
	public byte[] getSessionIdentifier() {
		return sessionIdentifier;
	}

	/**
	 * Disconnect from the remote host. No more messages can be sent after this
	 * method has been called.
	 * 
	 * @param reason
	 * @param disconnectReason
	 *            , description
	 * @throws IOException
	 */
	public void disconnect(int reason, String disconnectReason) {

		ByteArrayWriter baw = new ByteArrayWriter();

		try {
			this.disconnectReason = disconnectReason;

			baw.write(SSH_MSG_DISCONNECT);
			baw.writeInt(reason);
			baw.writeString(disconnectReason);
			baw.writeString("");

			Log.info(this, "Sending SSH_MSG_DISCONNECT ["
					+ disconnectReason + "]");

			sendMessage(baw.toByteArray(), true);

		} catch (Throwable t) {
		} finally {
			try {
				baw.close();
			} catch (IOException e) {
			}
			internalDisconnect();
		}
	}

	/**
	 * <p>
	 * Send a transport protocol message. The format of the message should be:
	 * <blockquote>
	 * 
	 * <pre>
	 * byte        Message ID
	 * byte[]      Payload
	 * </pre>
	 * 
	 * </blockquote>
	 * </p>
	 * 
	 * @param msgdata
	 * @throws IOException
	 */
	public void sendMessage(byte[] msgdata, boolean isActivity)
			throws SshException {

		synchronized (kexqueue) {

			if (currentState == PERFORMING_KEYEXCHANGE
					&& !isTransportMessage(msgdata[0])) {
				kexqueue.addElement(msgdata);
				return;
			}

			if (Log.isDebugEnabled()) {
				if (verbose) {
					Log.debug(this,
							"Sending transport protocol message");
				}
			}

			try {
				outgoingMessage.reset();

				int padding = 4;

				// Compress the payload if necersary
				if (outgoingCompression != null && isOutgoingCompressing) {
					msgdata = outgoingCompression.compress(msgdata, 0,
							msgdata.length);
				}

				// Determine the padding length
				padding += ((outgoingCipherLength - ((msgdata.length + 5 + padding) % outgoingCipherLength)) % outgoingCipherLength);

				// Write the packet length field
				outgoingMessage.writeInt(msgdata.length + 1 + padding);

				// Write the padding length
				outgoingMessage.write(padding);

				// Write the message payload
				outgoingMessage.write(msgdata, 0, msgdata.length);

				// Create some random data for the padding
				ComponentManager
						.getInstance()
						.getRND()
						.nextBytes(outgoingMessage.array(),
								outgoingMessage.size(), padding);
				outgoingMessage.move(padding);

				// Generate the MAC
				if (outgoingMac != null) {
					outgoingMac.generate(outgoingSequence,
							outgoingMessage.array(), 0, outgoingMessage.size(),
							outgoingMessage.array(), outgoingMessage.size());

				}

				// Perfrom encrpytion
				if (encryption != null) {
					encryption.transform(outgoingMessage.array(), 0,
							outgoingMessage.array(), 0, outgoingMessage.size());
				}

				outgoingMessage.move(outgoingMacLength);
				outgoingBytes += outgoingMessage.size();

				// Send!
				transportOut.write(outgoingMessage.array(), 0,
						outgoingMessage.size());
				transportOut.flush();

				if (isActivity)
					lastActivity = System.currentTimeMillis();

				if (Log.isDebugEnabled()) {
					if (verbose) {
						Log.debug(
								this,
								"Sent "
										+ outgoingMessage.size()
										+ " bytes of transport data outgoingSequence="
										+ outgoingSequence
										+ " totalBytesSinceKEX="
										+ numOutgoingBytesSinceKEX);
					}
				}

				outgoingSequence++;
				numOutgoingBytesSinceKEX += msgdata.length;
				numOutgoingPacketsSinceKEX++;

				if (outgoingSequence >= 4294967296L) {
					outgoingSequence = 0;
				}

				if (!transportContext.isKeyReExchangeDisabled()) {
					if (numOutgoingBytesSinceKEX >= MAX_NUM_BYTES_BEFORE_REKEY
							|| numOutgoingPacketsSinceKEX >= MAX_NUM_PACKETS_BEFORE_REKEY) {

						if (Log.isDebugEnabled()) {
							Log.debug(this,
									"Requesting key re-exchange");
						}
						sendKeyExchangeInit(false);
					}
				}
			} catch (IOException ex) {
				internalDisconnect();
				throw new SshException("Unexpected termination: "
						+ ex.getMessage(), SshException.UNEXPECTED_TERMINATION);
			}
		}

	}

	/**
	 * Get the next message. The message returned will be the full message data
	 * so skipping the first 5 bytes is required before the message data can be
	 * read.
	 * 
	 * @return a byte array containing all the message data
	 * @throws IOException
	 */
	public byte[] nextMessage() throws SshException {
		if (Log.isDebugEnabled()) {
			if (verbose) {
				Log.debug(this, "transport next message");
			}
		}
		synchronized (transportIn) {

			byte[] msg;

			do {
				msg = readMessage();
			} while (processMessage(msg));
			return msg;
		}

	}

	void readWithTimeout(byte[] buf, int off, int len, int timeoutMillis,
			boolean isPartialMessage) throws SshException {

		int count = 0;

		int timeout = 0;

		if (isPartialMessage) {
			// save current timeout value and restore later
			timeout = configureSocketTimeout(transportContext
					.getPartialMessageTimeout());
		}

		try {
			do {
				try {
					int read = transportIn.read(buf, off + count, len - count);

					if (read == -1)
						throw new SshException("EOF received from remote side",
								SshException.UNEXPECTED_TERMINATION);

					count += read;

				} catch (InterruptedIOException ex) {

					if (Log.isDebugEnabled()) {
						Log.debug(this,
								"Socket timed out during read! "
										+ " isPartialMessage="
										+ isPartialMessage
										+ " bytesTransfered="
										+ ex.bytesTransferred);
					}

					if (isPartialMessage) {
						if (ex.bytesTransferred > 0) {
							count += ex.bytesTransferred;
							continue;
						}
					}

					if (isPartialMessage) {
						internalDisconnect();
						throw new SshException(
								"Remote host failed to respond during message receive!",
								SshException.SOCKET_TIMEOUT);
					} else {

						if (getContext().getIdleConnectionTimeoutSeconds() > 0
								&& (System.currentTimeMillis() - lastActivity) > (getContext()
										.getIdleConnectionTimeoutSeconds() * 1000)) {

							if (Log.isDebugEnabled()) {
								Log.debug(
										this,
										"Connection is idle, disconnecting idleMax="
												+ getContext()
														.getIdleConnectionTimeoutSeconds());
							}
							disconnect(TransportProtocol.BY_APPLICATION,
									"Idle connection");
							throw new SshException(
									"Connection has been dropped as it reached max idle time of "
											+ getContext()
													.getIdleConnectionTimeoutSeconds()
											+ " seconds.",
									SshException.CONNECTION_CLOSED);
						} else if (getContext().isSendIgnorePacketOnIdle()) {
							ByteArrayWriter baw = new ByteArrayWriter();
							try {
								if (Log.isDebugEnabled()) {
									Log.debug(this,
											"Sending SSH_MSG_IGNORE");
								}

								baw.write(SSH_MSG_IGNORE);
								int tmplen = (int) (Math.random()
										* (getContext()
												.getKeepAliveMaxDataLength()) + 1);
								byte[] tmp = new byte[tmplen];
								ComponentManager.getInstance().getRND()
										.nextBytes(tmp);
								baw.writeBinaryString(tmp);

								sendMessage(baw.toByteArray(), false);

							} catch (IOException e) {
								// Disconnected
								internalDisconnect(
										"Connection failed during SSH_MSG_IGNORE packet",
										CONNECTION_LOST);
							} finally {
								try {
									baw.close();
								} catch (IOException e) {
								}
							}
						}

						if (getContext().getSocketTimeout() > 0) {

							for (Enumeration<TransportProtocolListener> e = listeners
									.elements(); e.hasMoreElements();) {
								TransportProtocolListener l = e.nextElement();
								try {
									l.onIdle(lastActivity);
								} catch (Throwable t) {
								}
							}
						} else {
							throw new SshException(
									"Socket connection timed out.",
									SshException.SOCKET_TIMEOUT);
						}

					}

					/**
					 * throw new SshException( "Socket connection timed out.",
					 * SshException.SOCKET_TIMEOUT);
					 **/

				} catch (IOException ex) {
					throw new SshException("IO error received from remote"
							+ ex.getMessage(),
							SshException.UNEXPECTED_TERMINATION, ex);
				}
			} while (count < len);
		} finally {
			if (isPartialMessage) {
				// set socket timeout back to its original value
				configureSocketTimeout(timeout);
			}
		}
	}

	private int configureSocketTimeout(int timeout) {

		if (provider instanceof SocketTimeoutSupport) {
			try {
				SocketTimeoutSupport sock = (SocketTimeoutSupport) provider;
				int ret = sock.getSoTimeout();
				sock.setSoTimeout(timeout);
				return ret;
			} catch (IOException ex) {
			}
		}

		return 0;
	}

	byte[] readMessage() throws SshException {
		if (Log.isDebugEnabled()) {
			if (verbose) {
				Log.debug(this, "transport read message");
			}
		}

		synchronized (transportIn) {

			try {

				if (Log.isDebugEnabled()) {
					if (verbose) {
						Log.debug(this, "Waiting for transport message");
					}
				}

				readWithTimeout(incomingMessage, 0, incomingCipherLength,
						transportContext.getPartialMessageTimeout(), false);

				// Decrypt the data if we have a valid cipher
				if (decryption != null) {
					decryption.transform(incomingMessage, 0, incomingMessage,
							0, incomingCipherLength);

					// Preview the message length
				}
				int msglen = (int) ByteArrayReader.readInt(incomingMessage, 0);

				if (msglen <= 0)
					throw new SshException(
							"Server sent invalid message length of " + msglen
									+ "!", SshException.PROTOCOL_VIOLATION);

				int padlen = (incomingMessage[4] & 0xFF);
				int remaining = (msglen - (incomingCipherLength - 4));

				if (Log.isDebugEnabled()) {
					if (verbose) {
						Log.debug(this,
								"Incoming transport message msglen=" + msglen
										+ " padlen=" + padlen);
					}
				}

				// Verify that the packet length is good
				if (remaining < 0) {
					internalDisconnect();
					throw new SshException(
							"EOF whilst reading message data block",
							SshException.UNEXPECTED_TERMINATION);
				} else if (remaining > incomingMessage.length
						- incomingCipherLength) {

					if (remaining + incomingCipherLength + incomingMacLength > transportContext
							.getMaximumPacketLength()) {
						internalDisconnect();
						throw new SshException(
								"Incoming packet length violates SSH protocol ["
										+ remaining + incomingCipherLength
										+ " bytes]",
								SshException.UNEXPECTED_TERMINATION);
					}
					// Resize the incomingMessage buffer
					byte[] tmp = new byte[remaining + incomingCipherLength
							+ incomingMacLength];
					System.arraycopy(incomingMessage, 0, tmp, 0,
							incomingCipherLength);
					incomingMessage = tmp;

				}

				// Read, decrypt and save the remaining data
				if (remaining > 0) {

					readWithTimeout(incomingMessage, incomingCipherLength,
							remaining,
							transportContext.getPartialMessageTimeout(), true);

					if (decryption != null) {
						decryption.transform(incomingMessage,
								incomingCipherLength, incomingMessage,
								incomingCipherLength, remaining);
					}
					// Verify the message
				}
				if (incomingMac != null) {
					readWithTimeout(incomingMessage, incomingCipherLength
							+ remaining, incomingMacLength,
							transportContext.getPartialMessageTimeout(), true);

					// Verify the mac
					if (!incomingMac.verify(incomingSequence, incomingMessage,
							0, incomingCipherLength + remaining,
							incomingMessage, incomingCipherLength + remaining)) {
						disconnect(TransportProtocol.MAC_ERROR,
								"Corrupt Mac on input");
						throw new SshException("Corrupt Mac on input",
								SshException.PROTOCOL_VIOLATION);
					}
				}

				if (++incomingSequence >= 4294967296L) {
					incomingSequence = 0;
				}

				incomingBytes += incomingCipherLength + remaining
						+ incomingMacLength;

				byte[] payload = new byte[(msglen + 4) - padlen - 5];
				System.arraycopy(incomingMessage, 5, payload, 0, payload.length);

				// Uncompress the message payload if necersary
				if (incomingCompression != null && isIncomingCompressing) {
					return incomingCompression.uncompress(payload, 0,
							payload.length);
				}

				numIncomingBytesSinceKEX += payload.length;
				numIncomingPacketsSinceKEX++;

				if (!transportContext.isKeyReExchangeDisabled()) {
					if (numIncomingBytesSinceKEX >= MAX_NUM_BYTES_BEFORE_REKEY
							|| numIncomingPacketsSinceKEX >= MAX_NUM_PACKETS_BEFORE_REKEY) {
						sendKeyExchangeInit(false);
					}
				}

				if (Log.isDebugEnabled()) {
					if (verbose) {
						Log.debug(this,
								"Completed incoming transport message");
					}
				}
				return payload;
			} catch (InterruptedIOException ex) {
				throw new SshException(
						"Interrupted IO; possible socket timeout detected?",
						SshException.SOCKET_TIMEOUT);
			} catch (IOException ex) {
				internalDisconnect();
				throw new SshException("Unexpected terminaton: "
						+ (ex.getMessage() != null ? ex.getMessage() : ex
								.getClass().getName()) + " sequenceNo = "
						+ incomingSequence + " bytesIn = " + incomingBytes
						+ " bytesOut = " + outgoingBytes,
						SshException.UNEXPECTED_TERMINATION, ex);
			}
		}

	}

	public SshKeyExchangeClient getKeyExchange() {
		return keyExchange;
	}

	public static boolean Arrayequals(byte[] a, byte[] a2) {
		if (a == a2)
			return true;
		if (a == null || a2 == null)
			return false;

		int length = a.length;
		if (a2.length != length)
			return false;

		for (int i = 0; i < length; i++)
			if (a[i] != a2[i])
				return false;

		return true;
	}

	void performKeyExchange(byte[] msg) throws SshException {

		ByteArrayReader bar = new ByteArrayReader(msg, 0, msg.length);
		try {
			synchronized (kexqueue) {

				// If were not already in a key exchange state then send our kex
				// init
				if (localkex == null) {
					sendKeyExchangeInit(false);
				}

				// Set the state to performing key exchange now that we have
				// both msgs
				currentState = TransportProtocol.PERFORMING_KEYEXCHANGE;

				// Extract the remote's side kex init taking away the header and
				// padding
				remotekex = msg;

				bar.skip(17);

				String remoteKeyExchanges = checkValidString("key exchange",
						bar.readString());
				String remotePublicKeys = checkValidString("public key",
						bar.readString());
				String remoteCiphersCS = checkValidString(
						"client->server cipher", bar.readString());
				String remoteCiphersSC = checkValidString(
						"server->client cipher", bar.readString());
				String serverCSMacs = checkValidString("client->server mac",
						bar.readString());
				String serverSCMacs = checkValidString("server->client mac",
						bar.readString());
				String serverCSCompressions = checkValidString(
						"client->server comp", bar.readString());
				String serverSCCompressions = checkValidString(
						"server->client comp", bar.readString());
				@SuppressWarnings("unused")
				String lang1 = bar.readString();
				@SuppressWarnings("unused")
				String lang2 = bar.readString();

				boolean guessed = bar.readBoolean();

				EventServiceImplementation
						.getInstance()
						.fireEvent(
								(new Event(
										this,
										J2SSHEventCodes.EVENT_KEY_EXCHANGE_INIT,
										true))
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_REMOTE_KEY_EXCHANGES,
												remoteKeyExchanges)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_LOCAL_KEY_EXCHANGES,
												transportContext
														.supportedKeyExchanges()
														.list(transportContext
																.getPreferredKeyExchange()))
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_REMOTE_PUBLICKEYS,
												remotePublicKeys)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_LOCAL_PUBLICKEYS,
												transportContext
														.supportedPublicKeys()
														.list(transportContext
																.getPreferredPublicKey()))
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_REMOTE_CIPHERS_CS,
												remoteCiphersCS)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_LOCAL_CIPHERS_CS,
												transportContext
														.supportedCiphersCS()
														.list(transportContext
																.getPreferredCipherCS()))
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_REMOTE_CIPHERS_SC,
												remoteCiphersSC)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_LOCAL_CIPHERS_SC,
												transportContext
														.supportedCiphersSC()
														.list(transportContext
																.getPreferredCipherSC()))
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_REMOTE_CS_MACS,
												serverCSMacs)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_LOCAL_CS_MACS,
												transportContext
														.supportedMacsCS()
														.list(transportContext
																.getPreferredMacCS()))
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_REMOTE_SC_MACS,
												serverSCMacs)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_LOCAL_SC_MACS,
												transportContext
														.supportedMacsSC()
														.list(transportContext
																.getPreferredMacSC()))
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_REMOTE_CS_COMPRESSIONS,
												serverCSCompressions)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_LOCAL_CS_COMPRESSIONS,
												transportContext
														.supportedCompressionsCS()
														.list(transportContext
																.getPreferredCompressionCS()))
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_REMOTE_SC_COMPRESSIONS,
												serverSCCompressions)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_LOCAL_SC_COMPRESSIONS,
												transportContext
														.supportedCompressionsSC()
														.list(transportContext
																.getPreferredCompressionSC())));

				if (Log.isDebugEnabled()) {
					Log.debug(this,
							"Remote computer supports key exchanges: "
									+ remoteKeyExchanges);
				}

				if (Log.isDebugEnabled()) {
					Log.debug(this,
							"Remote computer supports public keys: "
									+ remotePublicKeys);
				}

				if (Log.isDebugEnabled()) {
					Log.debug(this,
							"Remote computer supports client->server ciphers: "
									+ remoteCiphersCS);
				}

				String cipherCS = selectNegotiatedComponent(
						transportContext.supportedCiphersCS().list(
								transportContext.getPreferredCipherCS()),
						remoteCiphersCS);

				if (Log.isDebugEnabled()) {
					Log.debug(this,
							"Negotiated client->server cipher: " + cipherCS);
				}

				if (Log.isDebugEnabled()) {
					Log.debug(this,
							"Remote computer supports client->server ciphers: "
									+ remoteCiphersCS);
				}

				String cipherSC = selectNegotiatedComponent(
						transportContext.supportedCiphersSC().list(
								transportContext.getPreferredCipherSC()),
						remoteCiphersSC);

				if (Log.isDebugEnabled()) {
					Log.debug(this,
							"Negotiated server->client cipher: " + cipherSC);
				}

				SshCipher encryption = (SshCipher) transportContext
						.supportedCiphersCS().getInstance(cipherCS);

				SshCipher decryption = (SshCipher) transportContext
						.supportedCiphersSC().getInstance(cipherSC);
				String macCS = selectNegotiatedComponent(
						transportContext.supportedMacsCS().list(
								transportContext.getPreferredMacCS()),
						checkValidString("client->server hmac", serverCSMacs));

				String macSC = selectNegotiatedComponent(
						transportContext.supportedMacsSC().list(
								transportContext.getPreferredMacSC()),
						checkValidString("server->client hmac", serverSCMacs));

				SshHmac outgoingMac = (SshHmac) transportContext
						.supportedMacsCS().getInstance(macCS);

				SshHmac incomingMac = (SshHmac) transportContext
						.supportedMacsSC().getInstance(macSC);

				String compressionCS = selectNegotiatedComponent(
						transportContext.supportedCompressionsCS().list(
								transportContext.getPreferredCompressionCS()),
						checkValidString("client->server compression",
								serverCSCompressions));

				String compressionSC = selectNegotiatedComponent(
						transportContext.supportedCompressionsSC().list(
								transportContext.getPreferredCompressionSC()),
						checkValidString("server->client compression",
								serverSCCompressions));

				SshCompression outgoingCompression = null;

				if (!compressionCS.equals(Ssh2Context.COMPRESSION_NONE)) {
					outgoingCompression = (SshCompression) transportContext
							.supportedCompressionsCS().getInstance(
									compressionCS);
					outgoingCompression.init(SshCompression.DEFLATER, 6);
				}

				SshCompression incomingCompression = null;

				if (!compressionSC.equals(Ssh2Context.COMPRESSION_NONE)) {
					incomingCompression = (SshCompression) transportContext
							.supportedCompressionsSC().getInstance(
									compressionSC);
					incomingCompression.init(SshCompression.INFLATER, 6);
				}

				boolean ignoreFirstPacket = false;

				String keyExchangeAlg = selectNegotiatedComponent(
						transportContext.supportedKeyExchanges().list(
								transportContext.getPreferredKeyExchange()),
						remoteKeyExchanges);

				if (guessedKeyExchange == null
						|| !keyExchangeAlg.equals(guessedKeyExchange
								.getAlgorithm())) {
					// Determine the negotiated key exchange
					keyExchange = (SshKeyExchangeClient) transportContext
							.supportedKeyExchanges()
							.getInstance(keyExchangeAlg);
				}

				if (Log.isDebugEnabled()) {
					Log.debug(this, "Negotiated key exchange: "
							+ keyExchange.getAlgorithm());
				}

				if (guessed) {
					// Should we ignore the first key exchange packet?
					if (!keyExchangeAlg.equals(transportContext
							.getPreferredKeyExchange())) {
						ignoreFirstPacket = true;
					}
					String hostkey = selectNegotiatedComponent(
							transportContext.supportedPublicKeys().list(
									transportContext.getPreferredPublicKey()),
							remotePublicKeys);

					if (!ignoreFirstPacket
							&& !hostkey.equals(transportContext
									.getPreferredPublicKey())) {
						// Guess should be considered correct
						ignoreFirstPacket = true;
					}
				}

				keyExchange.init(this, ignoreFirstPacket);

				keyExchange.performClientExchange(localIdentification,
						remoteIdentification, localkex, remotekex);

				String hostKeyAlg = selectNegotiatedComponent(
						transportContext.supportedPublicKeys().list(
								transportContext.getPreferredPublicKey()),
						remotePublicKeys);
				hostkey = (SshPublicKey) transportContext.supportedPublicKeys()
						.getInstance(hostKeyAlg);

				if (!(ignoreHostKeyifEmpty && Arrayequals(
						keyExchange.getHostKey(), "".getBytes()))) {

					EventServiceImplementation.getInstance().fireEvent(
							(new Event(this,
									J2SSHEventCodes.EVENT_HOSTKEY_RECEIVED,
									true)).addAttribute(
									J2SSHEventCodes.ATTRIBUTE_HOST_KEY,
									new String(keyExchange.getHostKey())));
					hostkey.init(keyExchange.getHostKey(), 0,
							keyExchange.getHostKey().length);

					if (transportContext.getHostKeyVerification() != null) {
						if (!transportContext.getHostKeyVerification()
								.verifyHost(provider.getHost(), hostkey)) {
							EventServiceImplementation
									.getInstance()
									.fireEvent(
											new Event(
													this,
													J2SSHEventCodes.EVENT_HOSTKEY_REJECTED,
													false));
							disconnect(
									TransportProtocol.HOST_KEY_NOT_VERIFIABLE,
									"Host key not accepted");
							throw new SshException(
									"The host key was not accepted",
									SshException.CANCELLED_CONNECTION);
						}

						if (!hostkey.verifySignature(
								keyExchange.getSignature(),
								keyExchange.getExchangeHash())) {
							EventServiceImplementation
									.getInstance()
									.fireEvent(
											new Event(
													this,
													J2SSHEventCodes.EVENT_HOSTKEY_REJECTED,
													false));
							disconnect(
									TransportProtocol.HOST_KEY_NOT_VERIFIABLE,
									"Invalid host key signature");
							throw new SshException(
									"The host key signature is invalid",
									SshException.PROTOCOL_VIOLATION);
						}
						EventServiceImplementation.getInstance().fireEvent(
								new Event(this,
										J2SSHEventCodes.EVENT_HOSTKEY_ACCEPTED,
										true));
					}
				}

				// Set the first exchange hash as the session identifier
				if (sessionIdentifier == null) {
					sessionIdentifier = keyExchange.getExchangeHash();
				}

				// We now have all the necersary values to perform encrpytion
				// so lets send our new keys message and wait for the other
				// sides
				// response
				sendMessage(new byte[] { (byte) SSH_MSG_NEWKEYS }, true);

				// Put the outgoing components into use
				encryption.init(SshCipher.ENCRYPT_MODE, makeSshKey('A'),
						makeSshKey('C'));
				outgoingCipherLength = encryption.getBlockSize();

				outgoingMac.init(makeSshKey('E'));
				outgoingMacLength = outgoingMac.getMacLength();

				this.encryption = encryption;
				this.outgoingMac = outgoingMac;
				this.outgoingCompression = outgoingCompression;

				do {
					msg = readMessage();

					// Process the transport protocol message, must only be
					// SSH_MSH_INGORE, SSH_MSG_DEBUG, SSH_MSG_DISCONNECT or
					// SSH_MSG_NEWKEYS
					if (!processMessage(msg)) {
						EventServiceImplementation
								.getInstance()
								.fireEvent(
										new Event(
												this,
												J2SSHEventCodes.EVENT_KEY_EXCHANGE_FAILURE,
												true));
						disconnect(TransportProtocol.PROTOCOL_ERROR,
								"Invalid message received");
						throw new SshException(
								"Invalid message received during key exchange",
								SshException.PROTOCOL_VIOLATION);
					}

				} while (msg[0] != SSH_MSG_NEWKEYS);

				EventServiceImplementation
						.getInstance()
						.fireEvent(
								(new Event(
										this,
										J2SSHEventCodes.EVENT_KEY_EXCHANGE_COMPLETE,
										true))
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_USING_PUBLICKEY,
												hostKeyAlg)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_USING_KEY_EXCHANGE,
												keyExchangeAlg)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_USING_CS_CIPHER,
												cipherCS)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_USING_SC_CIPHER,
												cipherSC)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_USING_CS_MAC,
												macCS)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_USING_SC_MAC,
												macSC)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_USING_CS_COMPRESSION,
												compressionCS)
										.addAttribute(
												J2SSHEventCodes.ATTRIBUTE_USING_SC_COMPRESSION,
												compressionSC));

				// Put the incoming components into use
				decryption.init(SshCipher.DECRYPT_MODE, makeSshKey('B'),
						makeSshKey('D'));
				incomingCipherLength = decryption.getBlockSize();

				incomingMac.init(makeSshKey('F'));
				incomingMacLength = incomingMac.getMacLength();

				this.decryption = decryption;
				this.incomingMac = incomingMac;
				this.incomingCompression = incomingCompression;

				// Nasty hack for zlib@openssh.com compression type
				if (incomingCompression != null
						&& !incomingCompression.getAlgorithm().equals(
								"zlib@openssh.com"))
					isIncomingCompressing = true;

				if (outgoingCompression != null
						&& !outgoingCompression.getAlgorithm().equals(
								"zlib@openssh.com"))
					isOutgoingCompressing = true;

				// synchronized(kexqueue) {

				currentState = TransportProtocol.CONNECTED;

				for (Enumeration<byte[]> e = kexqueue.elements(); e
						.hasMoreElements();) {
					sendMessage(e.nextElement(), true);
				}
				kexqueue.removeAllElements();
				// }

				// Clean up and reset any parameters
				localkex = null;
				remotekex = null;
			}
		} catch (IOException ex) {
			EventServiceImplementation.getInstance().fireEvent(
					new Event(this, J2SSHEventCodes.EVENT_KEY_EXCHANGE_FAILURE,
							true));
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} catch (SshException sshe) {
			EventServiceImplementation.getInstance().fireEvent(
					new Event(this, J2SSHEventCodes.EVENT_KEY_EXCHANGE_FAILURE,
							true));
			throw sshe;
		} finally {
			try {
				bar.close();
			} catch (IOException e) {
			}
		}

	}

	void completedAuthentication() {
		if (incomingCompression != null
				&& incomingCompression.getAlgorithm()
						.equals("zlib@openssh.com"))
			isIncomingCompressing = true;

		if (outgoingCompression != null
				&& outgoingCompression.getAlgorithm()
						.equals("zlib@openssh.com"))
			isOutgoingCompressing = true;
	}

	/**
	 * Request that the remote server starts a transport protocol service. This
	 * is only available in CLIENT_MODE.
	 * 
	 * @param servicename
	 * @throws IOException
	 */
	public void startService(String servicename) throws SshException {

		ByteArrayWriter baw = new ByteArrayWriter();
		try {

			baw.write(SSH_MSG_SERVICE_REQUEST);
			baw.writeString(servicename);

			if (Log.isDebugEnabled()) {
				Log.debug(this, "Sending SSH_MSG_SERVICE_REQUEST");
			}

			sendMessage(baw.toByteArray(), true);

			byte[] msg;

			do {
				msg = readMessage();
			} while (processMessage(msg) || msg[0] != SSH_MSG_SERVICE_ACCEPT);

			if (Log.isDebugEnabled()) {
				Log.debug(this, "Received SSH_MSG_SERVICE_ACCEPT");
			}
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				baw.close();
			} catch (IOException e) {
			}
		}

	}

	void internalDisconnect(String msg, int reason) {
		currentState = DISCONNECTED;
		try {
			provider.close();
		} catch (IOException ex) {
		}

		for (Enumeration<TransportProtocolListener> e = listeners.elements(); e
				.hasMoreElements();) {
			TransportProtocolListener l = e.nextElement();
			try {
				l.onDisconnect(msg, reason);
			} catch (Throwable t) {
			}
		}

		for (int i = 0; i < shutdownHooks.size(); i++) {
			try {
				((Runnable) shutdownHooks.elementAt(i)).run();
			} catch (Throwable t) {
			}
		}
	}

	void internalDisconnect() {
		currentState = DISCONNECTED;
		try {
			provider.close();
		} catch (IOException ex) {
		}

		for (int i = 0; i < shutdownHooks.size(); i++) {
			try {
				((Runnable) shutdownHooks.elementAt(i)).run();
			} catch (Throwable t) {
			}
		}
	}

	void addShutdownHook(Runnable r) {
		if (r != null)
			shutdownHooks.addElement(r);
	}

	/**
	 * Process a message. This should be called when reading messages from
	 * outside of the transport protocol so that the transport protocol can
	 * parse its own messages.
	 * 
	 * @param msg
	 * @return <code>true</code> if the message was processed by the transport
	 *         and can be discarded, otherwise <code>false</code>.
	 * @throws SshException
	 */
	public boolean processMessage(byte[] msg) throws SshException {

		try {
			if (msg.length < 1) {
				disconnect(TransportProtocol.PROTOCOL_ERROR,
						"Invalid message received");
				throw new SshException("Invalid transport protocol message",
						SshException.INTERNAL_ERROR);
			}

			switch (msg[0]) {
			case SSH_MSG_DISCONNECT: {
				if (Log.isDebugEnabled()) {
					Log.debug(this, "Received SSH_MSG_DISCONNECT");
				}
				internalDisconnect();
				ByteArrayReader bar = new ByteArrayReader(msg, 5,
						msg.length - 5);
				try {
					EventServiceImplementation.getInstance().fireEvent(
							new Event(this,
									J2SSHEventCodes.EVENT_RECEIVED_DISCONNECT,
									true));
					throw new SshException(bar.readString(),
							SshException.REMOTE_HOST_DISCONNECTED);
				} finally {
					bar.close();
				}
			}
			case SSH_MSG_IGNORE: {
				if (Log.isDebugEnabled()) {
					Log.debug(this, "Received SSH_MSG_IGNORE");
				}

				return true;
			}
			case SSH_MSG_DEBUG: {
				lastActivity = System.currentTimeMillis();

				if (Log.isDebugEnabled()) {
					Log.debug(this, "Received SSH_MSG_DEBUG");
				}

				return true;
			}
			case SSH_MSG_NEWKEYS: {

				lastActivity = System.currentTimeMillis();

				if (Log.isDebugEnabled()) {
					Log.debug(this, "Received SSH_MSG_NEWKEYS");
				}

				return true;
			}
			case SSH_MSG_KEX_INIT: {

				lastActivity = System.currentTimeMillis();

				if (Log.isDebugEnabled()) {
					Log.debug(this, "Received SSH_MSG_KEX_INIT");
				}

				if (remotekex != null) {
					disconnect(TransportProtocol.PROTOCOL_ERROR,
							"Key exchange already in progress!");
					throw new SshException("Key exchange already in progress!",
							SshException.PROTOCOL_VIOLATION);
				}

				performKeyExchange(msg);

				return true;
			}
			default: {
				lastActivity = System.currentTimeMillis();
				// Not a transport protocol message
				return false;
			}
			}
		} catch (IOException ex1) {
			throw new SshException(ex1.getMessage(),
					SshException.INTERNAL_ERROR);
		}

	}

	boolean isTransportMessage(int messageid) {
		switch (messageid) {
		case SSH_MSG_DISCONNECT:
		case SSH_MSG_IGNORE:
		case SSH_MSG_DEBUG:
		case SSH_MSG_NEWKEYS:
		case SSH_MSG_KEX_INIT: {
			return true;
		}
		default: {
			if (keyExchange != null) {
				return keyExchange.isKeyExchangeMessage(messageid);
			}
			// Not a transport protocol message
			return false;
		}
		}
	}

	String selectNegotiatedComponent(String locallist, String remotelist)
			throws SshException {

		String list = remotelist;
		String llist = locallist;
		Vector<String> r = new Vector<String>();
		int idx;
		String name;
		while ((idx = list.indexOf(",")) > -1) {
			r.addElement(list.substring(0, idx).trim());
			list = list.substring(idx + 1).trim();
		}

		r.addElement(list.trim());

		while ((idx = llist.indexOf(",")) > -1) {
			name = llist.substring(0, idx).trim();
			if (r.contains(name)) {
				return name;
			}
			llist = llist.substring(idx + 1).trim();
		}

		if (r.contains(llist)) {
			return llist;
		}
		EventServiceImplementation
				.getInstance()
				.fireEvent(
						(new Event(
								this,
								J2SSHEventCodes.EVENT_FAILED_TO_NEGOTIATE_TRANSPORT_COMPONENT,
								true))
								.addAttribute(
										J2SSHEventCodes.ATTRIBUTE_LOCAL_COMPONENT_LIST,
										locallist)
								.addAttribute(
										J2SSHEventCodes.ATTRIBUTE_REMOTE_COMPONENT_LIST,
										remotelist));
		throw new SshException("Failed to negotiate a transport component ["
				+ locallist + "] [" + remotelist + "]",
				SshException.KEY_EXCHANGE_FAILED);

	}

	void sendKeyExchangeInit(boolean guess) throws SshException {
		ByteArrayWriter msg = new ByteArrayWriter();

		try {
			synchronized (kexqueue) {

				numIncomingBytesSinceKEX = 0;
				numIncomingPacketsSinceKEX = 0;
				numOutgoingBytesSinceKEX = 0;
				numOutgoingPacketsSinceKEX = 0;

				currentState = TransportProtocol.PERFORMING_KEYEXCHANGE;

				byte[] cookie = new byte[16];
				ComponentManager.getInstance().getRND().nextBytes(cookie);
				msg.write(SSH_MSG_KEX_INIT);
				msg.write(cookie);
				msg.writeString(transportContext.supportedKeyExchanges().list(
						transportContext.getPreferredKeyExchange()));
				msg.writeString(transportContext.supportedPublicKeys().list(
						transportContext.getPreferredPublicKey()));
				msg.writeString(transportContext.supportedCiphersCS().list(
						transportContext.getPreferredCipherCS()));
				msg.writeString(transportContext.supportedCiphersSC().list(
						transportContext.getPreferredCipherSC()));
				msg.writeString(transportContext.supportedMacsCS().list(
						transportContext.getPreferredMacCS()));
				msg.writeString(transportContext.supportedMacsSC().list(
						transportContext.getPreferredMacSC()));
				msg.writeString(transportContext.supportedCompressionsCS()
						.list(transportContext.getPreferredCompressionCS()));
				msg.writeString(transportContext.supportedCompressionsSC()
						.list(transportContext.getPreferredCompressionSC()));
				msg.writeString("");
				msg.writeString("");
				msg.writeBoolean(guess); // First packet follows
				msg.writeInt(0);

				if (Log.isDebugEnabled()) {
					Log.debug(this, "Sending SSH_MSG_KEX_INIT");
				}

				sendMessage(localkex = msg.toByteArray(), true);
			}

		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				msg.close();
			} catch (IOException e) {
			}
		}

	}

	byte[] makeSshKey(char chr) throws IOException {

		ByteArrayWriter keydata = new ByteArrayWriter();

		try {
			// Create the first 20 bytes of key data
			byte[] data = new byte[20];

			Digest hash = (Digest) ComponentManager.getInstance()
					.supportedDigests()
					.getInstance(keyExchange.getHashAlgorithm());

			// Put the dh k value
			hash.putBigInteger(keyExchange.getSecret());

			// Put in the exchange hash
			hash.putBytes(keyExchange.getExchangeHash());

			// Put in the character
			hash.putByte((byte) chr);

			// Put the exchange hash in again
			hash.putBytes(sessionIdentifier);

			// Create the fist 20 bytes
			data = hash.doFinal();

			keydata.write(data);

			// Now do the next 20
			hash.reset();

			// Put the dh k value in again
			hash.putBigInteger(keyExchange.getSecret());

			// And the exchange hash
			hash.putBytes(keyExchange.getExchangeHash());

			// Finally the first 20 bytes of data we created
			hash.putBytes(data);

			data = hash.doFinal();

			// Put it all together
			keydata.write(data);

			// Return it
			return keydata.toByteArray();
		} catch (SshException e) {
			throw new SshIOException(e);
		} finally {
			keydata.close();
		}

	}

	private String checkValidString(String id, String str) throws IOException {

		if (str.trim().equals(""))
			throw new IOException("Server sent invalid " + id + " value '"
					+ str + "'");

		StringTokenizer t = new StringTokenizer(str, ",");

		if (!t.hasMoreElements())
			throw new IOException("Server sent invalid " + id + " value '"
					+ str + "'");
		return str;
	}
}
