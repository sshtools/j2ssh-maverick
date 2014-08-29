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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Vector;

import com.sshtools.logging.Log;
import com.sshtools.ssh.ChannelEventListener;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshIOException;
import com.sshtools.ssh.message.Message;
import com.sshtools.ssh.message.MessageObserver;
import com.sshtools.ssh.message.SshAbstractChannel;
import com.sshtools.ssh.message.SshChannelMessage;
import com.sshtools.ssh.message.SshMessage;
import com.sshtools.ssh.message.SshMessageStore;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;

/**
 * <p>
 * All terminal sessions, forwarded connections, etc are channels and this class
 * implements the base SSH2 channel. Either side may open a channel and multiple
 * channels are multiplexed into a single SSH connection. SSH2 channels are flow
 * controlled, no data may be sent to a channel until a message is received to
 * indicate that window space is available.
 * </p>
 * 
 * <p>
 * To open a channel, first create an instance of the channel as follows:
 * <blockquote>
 * 
 * <pre>
 * Ssh2Channel channel = new Ssh2Channel(&quot;session&quot;, 32768, 32768);
 * </pre>
 * 
 * </blockquote> The second value passed into the constructor is the initial
 * window space and also the maximum amount of window space that will be
 * available to the other side. The channel manages the window space
 * automatically by increasing the amount available once the data has been read
 * from the channels InputStream and only when the current value falls below
 * half of the maximum.
 * </p>
 * 
 * <p>
 * After the channel has been created the channel is opened through a call to <a
 * href
 * ="Ssh2Client.html#openChannel(com.maverick.ssh.message.SshAbstractChannel)"
 * >openChannel(Ssh2Channel channel)</a>. Once the channel is open you can use
 * the IO streams to send and receive data.
 * </p>
 * 
 * 
 * @author Lee David Painter
 */
public class Ssh2Channel extends SshAbstractChannel {

	public static final String SESSION_CHANNEL = "session";

	ConnectionProtocol connection;
	int remoteid;
	String name;
	Vector<ChannelEventListener> listeners = new Vector<ChannelEventListener>();

	final static int SSH_MSG_CHANNEL_CLOSE = 97;
	final static int SSH_MSG_CHANNEL_EOF = 96;
	final static int SSH_MSG_CHANNEL_REQUEST = 98;

	final static int SSH_MSG_CHANNEL_SUCCESS = 99;
	final static int SSH_MSG_CHANNEL_FAILURE = 100;

	final static int SSH_MSG_WINDOW_ADJUST = 93;
	final static int SSH_MSG_CHANNEL_DATA = 94;
	final static int SSH_MSG_CHANNEL_EXTENDED_DATA = 95;

	boolean autoConsumeInput = false;
	boolean sendKeepAliveOnIdle = false;
	boolean isRemoteEOF = false;
	boolean isLocalEOF = false;

	final MessageObserver WINDOW_ADJUST_MESSAGES = new MessageObserver() {
		public boolean wantsNotification(Message msg) {
			switch (msg.getMessageId()) {
			case SSH_MSG_WINDOW_ADJUST:
			case SSH_MSG_CHANNEL_CLOSE:
				return true;
			default:
				return false;
			}
		}
	};

	final MessageObserver CHANNEL_DATA_MESSAGES = new MessageObserver() {
		public boolean wantsNotification(Message msg) {

			// Access to this observer is synchronized by the ThreadSynchronizer
			// so we can flag our InputStream as blocking when the method is
			// called and released once we have found a message
			switch (msg.getMessageId()) {
			case SSH_MSG_CHANNEL_DATA:
			case SSH_MSG_CHANNEL_EOF:
			case SSH_MSG_CHANNEL_CLOSE:
				return true;
			default:
				return false;
			}
		}
	};

	final MessageObserver EXTENDED_DATA_MESSAGES = new MessageObserver() {
		public boolean wantsNotification(Message msg) {
			switch (msg.getMessageId()) {
			case SSH_MSG_CHANNEL_EXTENDED_DATA:
			case SSH_MSG_CHANNEL_EOF:
			case SSH_MSG_CHANNEL_CLOSE:
				return true;
			default:
				return false;
			}
		}
	};

	final MessageObserver CHANNEL_REQUEST_MESSAGES = new MessageObserver() {
		public boolean wantsNotification(Message msg) {
			switch (msg.getMessageId()) {
			case SSH_MSG_CHANNEL_SUCCESS:
			case SSH_MSG_CHANNEL_FAILURE:
			case SSH_MSG_CHANNEL_CLOSE:
				return true;
			default:
				return false;
			}
		}
	};

	final MessageObserver CHANNEL_CLOSE_MESSAGES = new MessageObserver() {
		public boolean wantsNotification(Message msg) {
			switch (msg.getMessageId()) {
			case SSH_MSG_CHANNEL_CLOSE:
				return true;
			default:
				return false;
			}
		}
	};

	final static MessageObserver STICKY_MESSAGES = new MessageObserver() {
		public boolean wantsNotification(Message msg) {
			switch (msg.getMessageId()) {
			case SSH_MSG_CHANNEL_CLOSE:
			case SSH_MSG_CHANNEL_EOF:
				return true;
			default:
				return false;
			}
		}
	};

	ChannelInputStream in;
	ChannelOutputStream out;

	DataWindow localwindow;
	DataWindow remotewindow;

	boolean closing = false;
	boolean free = false;

	/**
	 * <p>
	 * Construct an SSH2 channel
	 * </p>
	 * 
	 * @param name
	 *            the name of the channel, for example "session"
	 * @param windowsize
	 *            the initial window size
	 * @param packetsize
	 *            the maximum packet size
	 */
	public Ssh2Channel(String name, int windowsize, int packetsize) {
		this.name = name;
		this.localwindow = new DataWindow(windowsize, packetsize);

		in = new ChannelInputStream(CHANNEL_DATA_MESSAGES);
		out = new ChannelOutputStream();
	}

	protected MessageObserver getStickyMessageIds() {
		return STICKY_MESSAGES;
	}

	public void setAutoConsumeInput(boolean autoConsumeInput) {
		this.autoConsumeInput = autoConsumeInput;
	}

	long getWindowSize() {
		return localwindow.available();
	}

	int getPacketSize() {
		return localwindow.getPacketSize();
	}

	protected SshMessageStore getMessageStore() throws SshException {
		return super.getMessageStore();
	}

	/**
	 * Get the name of the channel.
	 * 
	 * @return the name of the channel.
	 */
	public String getName() {
		return name;
	}

	public InputStream getInputStream() {
		return in;
	}

	public OutputStream getOutputStream() {
		return out;
	}

	public void addChannelEventListener(ChannelEventListener listener) {
		synchronized (listeners) {
			if (listener != null) {
				listeners.addElement(listener);
			}
		}
	}

	public boolean isSendKeepAliveOnIdle() {
		return sendKeepAliveOnIdle;
	}

	public void setSendKeepAliveOnIdle(boolean sendKeepAliveOnIdle) {
		this.sendKeepAliveOnIdle = sendKeepAliveOnIdle;
	}

	public void idle() {

		if (sendKeepAliveOnIdle) {
			try {
				sendRequest("keep-alive@sshtools.com", false, null, false);
			} catch (SshException e) {
			}
		}
	}

	/**
	 * Called to initialize the channels variables when creating/opening.
	 * 
	 * @param connection
	 * @param channelid
	 */
	void init(ConnectionProtocol connection, int channelid) {
		this.connection = connection;
		super.init(connection, channelid);
	}

	/**
	 * Called after the channel has been created by the <a
	 * href="ChannelFactory.html>ChannelFactory</a>. There is no need to call
	 * this method directly, but it can be overridden to return data that should
	 * be returned in the SSH_MSG_CHANNEL_OPEN_CONFIRMATION message.
	 * 
	 * @return data that should be returned in the
	 *         SSH_MSG_CHANNEL_OPEN_CONFIRMATION message
	 * @throws IOException
	 */
	protected byte[] create() {
		return null;
	}

	/**
	 * Called once an SSH_MSG_CHANNEL_OPEN_CONFIRMATION has been sent.
	 * 
	 * @param remoteid
	 * @param remotewindow
	 * @param remotepacket
	 * @throws IOException
	 */
	protected void open(int remoteid, long remotewindow, int remotepacket)
			throws IOException {
		this.remoteid = remoteid;
		this.remotewindow = new DataWindow(remotewindow, remotepacket);

		this.state = CHANNEL_OPEN;

		synchronized (listeners) {
			for (Enumeration<ChannelEventListener> e = listeners.elements(); e
					.hasMoreElements();) {
				(e.nextElement()).channelOpened(this);
			}
		}
	}

	/**
	 * Once a SSH_MSG_CHANNEL_OPEN_CONFIRMATION message is received the
	 * framework calls this method to complete the channel open operation.
	 * 
	 * @param remoteid
	 *            the senders id
	 * @param remotewindow
	 *            the initial window space available for sending data
	 * @param remotepacket
	 *            the maximum packet size available for sending data
	 * @param responsedata
	 *            the data returned from the remote side in the
	 *            SSH_MSG_CHANNEL_OPEN_CONFIRMATION message
	 * @throws IOException
	 */
	protected void open(int remoteid, long remotewindow, int remotepacket,
			byte[] responsedata) throws IOException {

		open(remoteid, remotewindow, remotepacket);

	}

	/**
	 * Processes channel request messages by passing the request through to <a
	 * href
	 * ="#channelRequest(java.lang.String, boolean, byte[])">channelRequest()
	 * </a>.
	 */
	protected boolean processChannelMessage(SshChannelMessage msg)
			throws SshException {

		try {
			switch (msg.getMessageId()) {
			case SSH_MSG_CHANNEL_REQUEST:

				String requesttype = msg.readString();
				boolean wantreply = msg.read() != 0;
				byte[] requestdata = new byte[msg.available()];
				msg.read(requestdata);

				if (Log.isDebugEnabled()) {
					Log.debug(this,
							"Received SSH_MSG_CHANNEL_REQUEST id=" + channelid
									+ " rid=" + remoteid + " request="
									+ requesttype + " wantreply=" + wantreply);
				}
				channelRequest(requesttype, wantreply, requestdata);
				return true;
			case SSH_MSG_WINDOW_ADJUST:

				if (Log.isDebugEnabled()) {
					msg.mark(4);
					int len = (int) msg.readInt();
					Log.debug(this,
							"Received SSH_MSG_WINDOW_ADJUST id=" + channelid
									+ " rid=" + remoteid + " window="
									+ remotewindow.available() + " adjust="
									+ len);
					msg.reset();
				}

				return false;
			case SSH_MSG_CHANNEL_DATA:

				if (Log.isDebugEnabled()) {
					Log.debug(
							this,
							"Received SSH_MSG_CHANNEL_DATA id=" + channelid
									+ " rid=" + remoteid + " len="
									+ (msg.available() - 4) + " window="
									+ localwindow.available());
				}

				// Is the channels InputStream currently in a blocking read
				// operation? if it is then we can leave the message for it
				// to process (and subsequently break out of the block) or
				// if not we should process it here so that data events
				// are fired in a timely fashion
				if (autoConsumeInput) {
					localwindow.consume(msg.available() - 4);
					if (localwindow.available() <= localwindow.getInitialSize() / 2) {
						adjustWindow(localwindow.getInitialSize()
								- localwindow.available());
					}
				}

				for (Enumeration<ChannelEventListener> e = listeners.elements(); e
						.hasMoreElements();) {
					(e.nextElement()).dataReceived(Ssh2Channel.this,
							msg.array(), msg.getPosition() + 4,
							msg.available() - 4);
				}

				return autoConsumeInput;

			case SSH_MSG_CHANNEL_EXTENDED_DATA:

				if (Log.isDebugEnabled()) {
					Log.debug(this,
							"Received SSH_MSG_CHANNEL_EXTENDED_DATA id="
									+ channelid + " rid=" + remoteid + " len="
									+ (msg.available() - 4) + " window="
									+ localwindow.available());
				}

				int type = (int) ByteArrayReader.readInt(msg.array(),
						msg.getPosition());

				if (autoConsumeInput) {
					localwindow.consume(msg.available() - 8);
					if (localwindow.available() <= localwindow.getInitialSize() / 2) {
						adjustWindow(localwindow.getInitialSize()
								- localwindow.available());
					}
				}

				for (Enumeration<ChannelEventListener> e = listeners.elements(); e
						.hasMoreElements();) {
					(e.nextElement()).extendedDataReceived(Ssh2Channel.this,
							msg.array(), msg.getPosition() + 8,
							msg.available() - 8, type);
				}

				return autoConsumeInput;

			case SSH_MSG_CHANNEL_CLOSE:

				if (Log.isDebugEnabled()) {
					Log.debug(this,
							"Received SSH_MSG_CHANNEL_CLOSE id=" + channelid
									+ " rid=" + remoteid);
				}

				// Synchronize on message store and close
				synchronized (this) {
					if (!closing) {
						synchronized (ms) {
							if (!ms.isClosed())
								ms.close();
						}
					}
				}

				checkCloseStatus(true);
				return false;

			case SSH_MSG_CHANNEL_EOF:

				if (Log.isDebugEnabled()) {
					Log.debug(this, "Received SSH_MSG_CHANNEL_EOF id="
							+ channelid + " rid=" + remoteid);
				}

				isRemoteEOF = true;

				for (Enumeration<ChannelEventListener> e = listeners.elements(); e
						.hasMoreElements();) {
					(e.nextElement()).channelEOF(Ssh2Channel.this);
				}

				// Fire the EOF event, do we need this on the listener?
				channelEOF();

				if (isLocalEOF) {
					close();
				}
				return false;

			default:
				return false;
			}
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		}

	}

	SshChannelMessage processMessages(MessageObserver messagefilter)
			throws SshException, EOFException {

		SshChannelMessage msg;

		/**
		 * Collect the next channel message from the connection protocol
		 */
		msg = (SshChannelMessage) ms.nextMessage(messagefilter, 0);

		switch (msg.getMessageId()) {

		case SSH_MSG_WINDOW_ADJUST:

			try {

				remotewindow.adjust(msg.readInt());

				if (Log.isDebugEnabled()) {
					Log.debug(this, "Applied window adjust window="
							+ remotewindow.available());
				}
			} catch (IOException ex) {
				throw new SshException(SshException.INTERNAL_ERROR, ex);
			}
			break;

		case SSH_MSG_CHANNEL_DATA:

			try {
				int length = (int) msg.readInt();
				processStandardData(length, msg);
			} catch (IOException e) {
				throw new SshException(SshException.INTERNAL_ERROR, e);
			}
			break;

		case SSH_MSG_CHANNEL_EXTENDED_DATA:
			try {
				int type = (int) msg.readInt();
				int length = (int) msg.readInt();
				processExtendedData(type, length, msg);
			} catch (IOException ex) {
				throw new SshException(SshException.INTERNAL_ERROR, ex);
			}
			break;

		/**
		 * We dont remove these messages because other threads may be evaluating
		 * the messages at the same time
		 */
		case SSH_MSG_CHANNEL_CLOSE:
			checkCloseStatus(true);
			throw new EOFException("The channel is closed");

		case SSH_MSG_CHANNEL_EOF:
			throw new EOFException("The channel is EOF");

			/**
			 * Just return
			 */
		default:
			break;
		}

		return msg;
	}

	/**
	 * Called when channel data arrives, by default this method makes the data
	 * available in the channels InputStream. Override this method to change
	 * this behaviour.
	 * 
	 * @param buf
	 * @param offset
	 * @param len
	 * @throws IOException
	 */
	protected void processStandardData(int length, SshChannelMessage msg)
			throws SshException {
		in.addMessage(length, msg);
	}

	protected void processStandardData(byte[] buf, int off, int len)
			throws SshException {
		in.addMessage(len, new SshChannelMessage(SSH_MSG_CHANNEL_DATA, buf,
				off, len));
	}

	/**
	 * Called when extended data arrives. This method fires the
	 * {@link com.sshtools.ssh.ChannelEventListener#extendedDataReceived(com.maverick.ssh.Channel, byte[], int, int, int)}
	 * event so to maintain code compatibility <em>always</em> call the super
	 * method in any overidden method.
	 * 
	 * @param typecode
	 *            the type of extended data
	 * @param buf
	 *            the data buffer
	 * @param offset
	 *            the offset
	 * @param len
	 *            the length
	 * @throws SshException
	 * @throws IOException
	 */
	protected void processExtendedData(int typecode, int length,
			SshChannelMessage msg) throws SshException {
		// Default implementation is to ignore extended data
	}

	/**
	 * Currently reserved.
	 * 
	 * @return ChannelInputStream
	 */
	protected ChannelInputStream createExtendedDataStream() {
		return new ChannelInputStream(EXTENDED_DATA_MESSAGES);
	}

	void sendChannelData(byte[] buf, int offset, int len) throws SshException {

		ByteArrayWriter msg = new ByteArrayWriter(len + 9);

		try {
			if (state != CHANNEL_OPEN) {
				throw new SshException("The channel is closed",
						SshException.CHANNEL_FAILURE);
			}

			if (len > 0) {
				msg.write(SSH_MSG_CHANNEL_DATA);
				msg.writeInt(remoteid);
				msg.writeBinaryString(buf, offset, len);

				if (Log.isDebugEnabled()) {
					Log.debug(this, "Sending SSH_MSG_CHANNEL_DATA id="
							+ channelid + " rid=" + remoteid + " len=" + len
							+ " window=" + remotewindow.available());
				}

				connection.sendMessage(msg.toByteArray(), true);
			}

			for (Enumeration<ChannelEventListener> e = listeners.elements(); e
					.hasMoreElements();) {
				(e.nextElement()).dataSent(Ssh2Channel.this, buf, offset, len);
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

	void sendExtendedChannelData(byte[] buf, int offset, int len, int type)
			throws SshException {

		ByteArrayWriter msg = new ByteArrayWriter(len + 9);

		try {
			if (state != CHANNEL_OPEN) {
				throw new SshException("The channel is closed",
						SshException.CHANNEL_FAILURE);
			}

			if (len > 0) {

				msg.write(SSH_MSG_CHANNEL_EXTENDED_DATA);
				msg.writeInt(remoteid);
				msg.writeInt(type);
				msg.writeBinaryString(buf, offset, len);

				connection.sendMessage(msg.toByteArray(), true);
			}

			if (listeners != null) {
				for (int i = 0; i < listeners.size(); i++) {
					((ChannelEventListener) listeners.elementAt(i))
							.extendedDataReceived(Ssh2Channel.this, buf,
									offset, len, type);
				}
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

	private void adjustWindow(long increment) throws SshException {

		ByteArrayWriter msg = new ByteArrayWriter(9);

		try {
			// Check that the channel isn't closing
			if (closing || isClosed())
				return;

			msg.write(SSH_MSG_WINDOW_ADJUST);
			msg.writeInt(remoteid);
			msg.writeInt(increment);

			if (Log.isDebugEnabled()) {
				Log.debug(this, "Sending SSH_MSG_WINDOW_ADJUST id="
						+ channelid + " rid=" + remoteid + " window="
						+ localwindow.available() + " adjust=" + increment);
			}
			localwindow.adjust(increment);

			connection.sendMessage(msg.toByteArray(), true);
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				msg.close();
			} catch (IOException e) {
			}
		}

	}

	/**
	 * Sends a channel request. Many channels have extensions that are specific
	 * to that particular channel type, an example of which is requesting a
	 * pseudo terminal from an interactive session.
	 * 
	 * @param requesttype
	 *            the name of the request, for example "pty-req"
	 * @param wantreply
	 *            specifies whether the remote side should send a
	 *            success/failure message
	 * @param requestdata
	 *            the request data
	 * @return <code>true</code> if the request succeeded and wantreply=true,
	 *         otherwise <code>false</code>
	 * @throws IOException
	 */
	public boolean sendRequest(String requesttype, boolean wantreply,
			byte[] requestdata) throws SshException {
		return sendRequest(requesttype, wantreply, requestdata, true);
	}

	/**
	 * Sends a channel request. Many channels have extensions that are specific
	 * to that particular channel type, an example of which is requesting a
	 * pseudo terminal from an interactive session.
	 * 
	 * @param requesttype
	 *            the name of the request, for example "pty-req"
	 * @param wantreply
	 *            specifies whether the remote side should send a
	 *            success/failure message
	 * @param requestdata
	 *            the request data
	 * @param isActivity
	 * @return <code>true</code> if the request succeeded and wantreply=true,
	 *         otherwise <code>false</code>
	 * @throws IOException
	 */
	public boolean sendRequest(String requesttype, boolean wantreply,
			byte[] requestdata, boolean isActivity) throws SshException {

		synchronized (this) {
			ByteArrayWriter msg = new ByteArrayWriter();
			try {
				msg.write(SSH_MSG_CHANNEL_REQUEST);
				msg.writeInt(remoteid);
				msg.writeString(requesttype);
				msg.writeBoolean(wantreply);
				if (requestdata != null) {
					msg.write(requestdata);

				}

				if (Log.isDebugEnabled()) {
					Log.debug(this,
							"Sending SSH_MSG_CHANNEL_REQUEST id=" + channelid
									+ " rid=" + remoteid + " request="
									+ requesttype + " wantreply=" + wantreply);
				}
				connection.sendMessage(msg.toByteArray(), true);

				boolean result = false;

				if (wantreply) {
					SshMessage reply = processMessages(CHANNEL_REQUEST_MESSAGES);
					return reply.getMessageId() == SSH_MSG_CHANNEL_SUCCESS;
				}

				return result;

			} catch (IOException ex) {
				throw new SshException(ex, SshException.INTERNAL_ERROR);
			} finally {
				try {
					msg.close();
				} catch (IOException e) {
				}
			}
		}

	}

	/**
	 * Closes the channel. No data may be sent or receieved after this method
	 * completes.
	 */
	public void close() {

		boolean performClose = false;
		;

		synchronized (this) {
			if (!closing && state == CHANNEL_OPEN) {
				performClose = closing = true;
			}
		}

		if (performClose) {

			synchronized (listeners) {
				for (Enumeration<ChannelEventListener> e = listeners.elements(); e
						.hasMoreElements();) {
					(e.nextElement()).channelClosing(this);
				}
			}

			try {
				// Close the ChannelOutputStream
				out.close(!isLocalEOF);

				// Send our close message
				ByteArrayWriter msg = new ByteArrayWriter(5);
				msg.write(SSH_MSG_CHANNEL_CLOSE);
				msg.writeInt(remoteid);

				try {
					if (Log.isDebugEnabled()) {
						Log.debug(this,
								"Sending SSH_MSG_CHANNEL_CLOSE id=" + channelid
										+ " rid=" + remoteid);
					}
					connection.sendMessage(msg.toByteArray(), true);
				} catch (SshException ex1) {
					if (Log.isDebugEnabled()) {
						Log.debug(this,
								"Exception attempting to send SSH_MSG_CHANNEL_CLOSE id="
										+ channelid + " rid=" + remoteid, ex1);
					}
				} finally {
					msg.close();
				}

				this.state = CHANNEL_CLOSED;

			} catch (EOFException eof) {
				// Ignore this is the message store informing of close/eof
			} catch (SshIOException ex) {
				if (Log.isDebugEnabled()) {
					Log.debug(this,
							"SSH Exception during close reason="
									+ ex.getRealException().getReason()
									+ " id=" + channelid + " rid=" + remoteid,
							ex.getRealException());
				}
				// IO Error during close so the connection has dropped
				connection.transport.disconnect(
						TransportProtocol.CONNECTION_LOST,
						"IOException during channel close: " + ex.getMessage());
			} catch (IOException ex) {
				if (Log.isDebugEnabled()) {
					Log.debug(this, "Exception during close id="
							+ channelid + " rid=" + remoteid, ex);
				}
				// IO Error during close so the connection has dropped
				connection.transport.disconnect(
						TransportProtocol.CONNECTION_LOST,
						"IOException during channel close: " + ex.getMessage());
			} finally {
				checkCloseStatus(ms.isClosed());
			}
		}
	}

	protected void checkCloseStatus(boolean remoteClosed) {

		if (state != CHANNEL_CLOSED) {
			close();
			if (!remoteClosed)
				remoteClosed = (ms.hasMessage(CHANNEL_CLOSE_MESSAGES) != null);
		}

		if (remoteClosed) {
			synchronized (this) {
				if (!free) {
					synchronized (listeners) {
						for (Enumeration<ChannelEventListener> e = listeners
								.elements(); e.hasMoreElements();) {
							(e.nextElement()).channelClosed(this);
						}
					}
					connection.closeChannel(this);
					free = true;
				}
			}
		}

	}

	/**
	 * This channel is equal to another channel if the channel id's are equal.
	 * Please note that channel numbers may be reused so this method should only
	 * be called on open channels.
	 */
	public boolean equals(Object obj) {
		if (obj instanceof Ssh2Channel) {
			return ((Ssh2Channel) obj).getChannelId() == channelid;
		}
		return false;
	}

	/**
	 * Called when a channel request is received, by default this method sends a
	 * failure message if the remote side requests a reply. Overidden methods
	 * should ALWAYS call this superclass method.
	 * 
	 * @param requesttype
	 *            the name of the request
	 * @param wantreply
	 *            specifies whether the remote side requires a success/failure
	 *            message
	 * @param requestdata
	 *            the request data
	 * @throws IOException
	 */
	protected void channelRequest(String requesttype, boolean wantreply,
			byte[] requestdata) throws SshException {
		if (wantreply) {
			ByteArrayWriter msg = new ByteArrayWriter();
			try {
				msg.write((byte) SSH_MSG_CHANNEL_FAILURE);
				msg.writeInt(remoteid);

				connection.sendMessage(msg.toByteArray(), true);
			} catch (IOException e) {
				throw new SshException(e, SshException.INTERNAL_ERROR);
			} finally {
				try {
					msg.close();
				} catch (IOException e) {
				}
			}
		}
	}

	/**
	 * Called when the remote side data stream is EOF, by default this method
	 * does nothing
	 * 
	 * @throws IOException
	 */
	protected void channelEOF() {

	}

	// / long transferedOut = 0;
	class ChannelOutputStream extends OutputStream {

		public void write(int b) throws IOException {
			write(new byte[] { (byte) b }, 0, 1);
		}

		public void write(byte[] buf, int offset, int len) throws IOException {

			try {
				long write;

				do {

					if (remotewindow.available() <= 0) {
						processMessages(WINDOW_ADJUST_MESSAGES);
					}

					synchronized (Ssh2Channel.this) {

						if (isLocalEOF) {
							throw new EOFException("The channel is EOF");
						}

						if (isClosed() || closing) {
							throw new EOFException("The channel is closed");
						}

						write = remotewindow.available() < remotewindow
								.getPacketSize() ? (remotewindow.available() < len ? remotewindow
								.available() : len)
								: (remotewindow.getPacketSize() < len ? remotewindow
										.getPacketSize() : len);

						if (write > 0) {
							sendChannelData(buf, offset, (int) write);
							remotewindow.consume((int) write);
							len -= write;
							offset += write;
						}
					}
				} while (len > 0);
			} catch (SshException ex) {
				throw new SshIOException(ex);
			}

		}

		public void close() throws IOException {
			close(!isClosed() && !isLocalEOF && !closing);
		}

		public void close(boolean sendEOF) throws IOException {
			if (sendEOF) {

				ByteArrayWriter msg = new ByteArrayWriter(5);
				msg.write(SSH_MSG_CHANNEL_EOF);
				msg.writeInt(remoteid);

				try {
					if (Log.isDebugEnabled()) {
						Log.debug(this,
								"Sending SSH_MSG_CHANNEL_EOF id="
										+ getChannelId() + " rid=" + remoteid);
					}
					connection.sendMessage(msg.toByteArray(), true);
				} catch (SshException ex) {
					throw new SshIOException(ex);
				} finally {
					msg.close();
				}
			}

			isLocalEOF = true;
			if (isRemoteEOF) {
				Ssh2Channel.this.close();
			}
		}

	}

	boolean isBlocking = false;

	class ChannelInputStream extends InputStream {

		int unread = 0;
		MessageObserver messagefilter;
		long transfered = 0;

		SshChannelMessage currentMessage = null;

		ChannelInputStream(MessageObserver messagefilter) {
			this.messagefilter = messagefilter;
		}

		void addMessage(int length, SshChannelMessage msg) {
			unread = length;
			currentMessage = msg;
		}

		/**
		 * This method returns the number of SSH messages that can be read using
		 * the read method without it blocking. In certain circumstances there
		 * may be more messages available but this method cannot discover them
		 * without blocking and so returns 0.
		 */
		public synchronized int available() throws IOException {

			try {
				if (unread == 0) {
					if (getMessageStore().hasMessage(messagefilter) != null) {
						processMessages(messagefilter);
					}
				}
				return unread;
			} catch (EOFException ex) {
				return -1;
			} catch (SshException ex) {
				throw new SshIOException(ex);
			}
		}

		public int read() throws IOException {
			byte[] b = new byte[1];
			int ret = read(b, 0, 1);

			if (ret > 0) {
				return b[0] & 0xFF;
			} else {
				return -1;
			}
		}

		/*
		 * public long skip(long len) throws IOException {
		 * 
		 * // Less complicated skip to ensure correct read mechanism is used.
		 * long count = 0; int r = 0; byte[] tmp = new byte[(int)len];
		 * while(count < len && r > -1) { r = read(tmp, 0, (int)(len - count));
		 * if(r > -1) { count += r; } } if(r==-1 && count==0) { throw new
		 * EOFException(); }
		 * 
		 * return count; }
		 */

		public synchronized int read(byte[] buf, int offset, int len)
				throws IOException {

			try {

				/*
				 * if there is a message available then processMessages, if its
				 * data then fills input buffer and sets unread
				 */
				if (available() == -1) {
					return -1;
				}

				while (unread <= 0 && !isClosed()) {
					processMessages(messagefilter);
				}

				int count = unread < len ? unread : len;

				if (count == 0 && isClosed()) {
					return -1;
				}

				currentMessage.read(buf, offset, count);
				localwindow.consume(count);
				unread -= count;

				if (System.getProperty("maverick.windowAdjustTest", "false")
						.equals("true")
						|| (unread + localwindow.available()) < (localwindow
								.getInitialSize() / 2)
						&& !isClosed()
						&& !closing) {
					adjustWindow(localwindow.getInitialSize()
							- localwindow.available() - unread);
				}

				transfered += count;

				return count;
			} catch (SshException ex) {
				throw new SshIOException(ex);
			} catch (EOFException ex) {
				return -1;
			}

		}
	}

	static class DataWindow {
		long windowsize;
		long initialSize;
		int packetsize;

		DataWindow(long windowsize, int packetsize) {
			this.initialSize = windowsize;
			this.windowsize = windowsize;
			this.packetsize = packetsize;
		}

		int getPacketSize() {
			return packetsize;
		}

		long getInitialSize() {
			return initialSize;
		}

		void adjust(long count) {
			windowsize += count;
		}

		void consume(int count) {

			windowsize -= count;
		}

		long available() {
			return windowsize;
		}
	}

}
