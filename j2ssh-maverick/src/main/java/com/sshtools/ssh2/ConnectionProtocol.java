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
import java.util.Hashtable;

import com.sshtools.events.EventLog;
import com.sshtools.ssh.ChannelOpenException;
import com.sshtools.ssh.SshContext;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.message.Message;
import com.sshtools.ssh.message.MessageObserver;
import com.sshtools.ssh.message.SshAbstractChannel;
import com.sshtools.ssh.message.SshChannelMessage;
import com.sshtools.ssh.message.SshMessage;
import com.sshtools.ssh.message.SshMessageRouter;
import com.sshtools.util.ByteArrayWriter;

/**
 * 
 * @author Lee David Painter
 */
class ConnectionProtocol extends SshMessageRouter implements
		TransportProtocolListener {

	/** The name of this service "ssh-connection" */
	public static final String SERVICE_NAME = "ssh-connection";

	final static int SSH_MSG_CHANNEL_OPEN = 90;
	final static int SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
	final static int SSH_MSG_CHANNEL_OPEN_FAILURE = 92;

	final static int SSH_MSG_GLOBAL_REQUEST = 80;
	final static int SSH_MSG_REQUEST_SUCCESS = 81;
	final static int SSH_MSG_REQUEST_FAILURE = 82;

	Object channelOpenLock = new Object();

	final static MessageObserver CHANNEL_OPEN_RESPONSE_MESSAGES = new MessageObserver() {
		public boolean wantsNotification(Message msg) {
			switch (msg.getMessageId()) {
			case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
			case SSH_MSG_CHANNEL_OPEN_FAILURE:
				return true;
			default:
				return false;
			}
		}
	};

	final static MessageObserver GLOBAL_REQUEST_MESSAGES = new MessageObserver() {
		public boolean wantsNotification(Message msg) {
			switch (msg.getMessageId()) {
			case SSH_MSG_REQUEST_SUCCESS:
			case SSH_MSG_REQUEST_FAILURE:
				return true;
			default:
				return false;
			}
		}
	};

	TransportProtocol transport;
	Hashtable<String,ChannelFactory> channelfactories = new Hashtable<String,ChannelFactory>();
	Hashtable<String,GlobalRequestHandler> requesthandlers = new Hashtable<String,GlobalRequestHandler>();

	public ConnectionProtocol(TransportProtocol transport, SshContext context,
			boolean buffered) {
		super(transport, context.getChannelLimit(), buffered);
		this.transport = transport;
		this.transport.addListener(this);
	}

	public void addChannelFactory(ChannelFactory factory) throws SshException {
		String[] types = factory.supportedChannelTypes();
		for (int i = 0; i < types.length; i++) {
			if (channelfactories.containsKey(types[i])) {
				throw new SshException(types[i]
						+ " channel is already registered!",
						SshException.BAD_API_USAGE);
			}
			channelfactories.put(types[i], factory);
		}
	}

	public void addRequestHandler(GlobalRequestHandler handler)
			throws SshException {
		String[] types = handler.supportedRequests();
		for (int i = 0; i < types.length; i++) {
			if (requesthandlers.containsKey(types[i])) {
				throw new SshException(types[i]
						+ " request is already registered!",
						SshException.BAD_API_USAGE);
			}
			requesthandlers.put(types[i], handler);
		}
	}

	public boolean sendGlobalRequest(GlobalRequest request, boolean wantreply)
			throws SshException {
		return sendGlobalRequest(request, wantreply, 0);
	}

	public boolean sendGlobalRequest(GlobalRequest request, boolean wantreply,
			long timeout) throws SshException {
		
		ByteArrayWriter msg = new ByteArrayWriter();
		try {
			
			msg.write(SSH_MSG_GLOBAL_REQUEST);
			msg.writeString(request.getName());
			msg.writeBoolean(wantreply);
			if (request.getData() != null) {
				msg.write(request.getData());

			}

			// #ifdef DEBUG
			EventLog.LogEvent(this, "Sending SSH_MSG_GLOBAL_REQUEST request="
					+ request.getName() + " wantreply=" + wantreply);
			// #endif
			sendMessage(msg.toByteArray(), true);

			if (wantreply) {
				SshMessage reply = getGlobalMessages().nextMessage(
						GLOBAL_REQUEST_MESSAGES, timeout);
				if (reply.getMessageId() == SSH_MSG_REQUEST_SUCCESS) {
					// #ifdef DEBUG
					EventLog.LogEvent(this,
							"Received SSH_MSG_REQUEST_SUCCESS request="
									+ request.getName());
					// #endif
					if (reply.available() > 0) {
						byte[] tmp = new byte[reply.available()];
						reply.read(tmp);
						request.setData(tmp);
					} else {
						request.setData(null);
					}
					return true;
				}
				// #ifdef DEBUG
				EventLog.LogEvent(
						this,
						"Received SSH_MSG_REQUEST_FAILURE request="
								+ request.getName());
				// #endif
				return false;
			}
			return true;
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				msg.close();
			} catch (IOException e) {
			}
		}
	}

	public void closeChannel(Ssh2Channel channel) {
		freeChannel(channel);
	}

	public SshContext getContext() {
		return transport.transportContext;
	}

	public void openChannel(Ssh2Channel channel, byte[] requestdata)
			throws SshException, ChannelOpenException {
		openChannel(channel, requestdata, 0);
	}
	
	public void openChannel(Ssh2Channel channel, byte[] requestdata, long timeout)
			throws SshException, ChannelOpenException {

		// synchronized(channelOpenLock) {
		try {

			int channelid = allocateChannel(channel);

			if (channelid == -1) {
				// #ifdef DEBUG
				EventLog.LogEvent(this,
						"Maximum number of channels exceeded! active="
								+ getChannelCount() + " channels="
								+ getMaxChannels());
				// #endif
				throw new ChannelOpenException(
						"Maximum number of channels exceeded",
						ChannelOpenException.RESOURCE_SHORTAGE);
			}

			channel.init(this, channelid);
			/*
			 * byte SSH_MSG_CHANNEL_OPEN string channel type in US-ASCII only
			 * uint32 sender channel uint32 initial window size uint32 maximum
			 * packet size .... channel type specific data follows
			 */
			ByteArrayWriter msg = new ByteArrayWriter();
			
			try {
				msg.write(SSH_MSG_CHANNEL_OPEN);
				msg.writeString(channel.getName());
				msg.writeInt(channel.getChannelId());
				msg.writeInt(channel.getWindowSize());
				msg.writeInt(channel.getPacketSize());
				if (requestdata != null) {
					msg.write(requestdata);
	
				}
	
				// #ifdef DEBUG
				EventLog.LogEvent(this, "Sending SSH_MSG_CHANNEL_OPEN type="
						+ channel.getName() + " id=" + channel.getChannelId()
						+ " window=" + channel.getWindowSize() + " packet="
						+ channel.getPacketSize());
				// #endif
				transport.sendMessage(msg.toByteArray(), true);

			} finally {
				try {
					msg.close();
				} catch (IOException e) {
				}
			}
			// #ifdef DEBUG
			// EventLog.LogEvent(this,"sent transport message, getting message stores next message");
			// #endif

			SshMessage reply = channel.getMessageStore().nextMessage(
					CHANNEL_OPEN_RESPONSE_MESSAGES, timeout);

			if (reply.getMessageId() == SSH_MSG_CHANNEL_OPEN_FAILURE) {

				// #ifdef DEBUG
				EventLog.LogEvent(
						this,
						"Received SSH_MSG_CHANNEL_OPEN_FAILURE id="
								+ channel.getChannelId());
				// #endif

				freeChannel(channel);
				int reason = (int) reply.readInt();
				throw new ChannelOpenException(reply.readString(), reason);
			}
			int remoteid = (int) reply.readInt();
			long remotewindow = reply.readInt();
			int remotepacket = (int) reply.readInt();
			byte[] responsedata = new byte[reply.available()];
			reply.read(responsedata);

			// #ifdef DEBUG
			EventLog.LogEvent(
					this,
					"Received SSH_MSG_CHANNEL_OPEN_CONFIRMATION id="
							+ channel.getChannelId() + " rid=" + remoteid
							+ " window=" + remotewindow + " packet="
							+ remotepacket);
			// #endif

			channel.open(remoteid, remotewindow, remotepacket, responsedata);

			return;
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		}
		// }

	}

	protected void sendMessage(byte[] msg, boolean isActivity)
			throws SshException {
		transport.sendMessage(msg, isActivity);
	}

	protected SshMessage createMessage(byte[] msg) throws SshException {

		if (msg[0] >= 91 && msg[0] <= 100) {
			return new SshChannelMessage(msg);
		}
		return new SshMessage(msg);
	}

	protected boolean processGlobalMessage(SshMessage message)
			throws SshException {

		/**
		 * We need to filter for any messages that require a response from the
		 * connection protocol such as channel open or global requests. These
		 * are not handled anywhere else within this implementation because
		 * doing so would require a thread to wait.
		 */

		try {
			switch (message.getMessageId()) {
			case SSH_MSG_CHANNEL_OPEN: {
				// Attempt to open the channel

				String type = message.readString();
				int remoteid = (int) message.readInt();
				int remotewindow = (int) message.readInt();
				int remotepacket = (int) message.readInt();
				byte[] requestdata = message.available() > 0 ? new byte[message
						.available()] : null;
				message.read(requestdata);

				// #ifdef DEBUG
				EventLog.LogEvent(this, "Received SSH_MSG_CHANNEL_OPEN rid="
						+ remoteid + " window=" + remotewindow + " packet="
						+ remotepacket);
				// #endif

				processChannelOpenRequest(type, remoteid, remotewindow,
						remotepacket, requestdata);
				return true;
			}
			case SSH_MSG_GLOBAL_REQUEST: {

				// Attempt to process the global request
				String requestname = message.readString();
				boolean wantreply = message.read() != 0;
				byte[] requestdata = new byte[message.available()];
				message.read(requestdata);

				// #ifdef DEBUG
				EventLog.LogEvent(this,
						"Received SSH_MSG_GLOBAL_REQUEST request="
								+ requestname + " wantreply=" + wantreply);
				// #endif

				// Process the request
				processGlobalRequest(requestname, wantreply, requestdata);
				return true;
			}
			default:
				return false;
			}
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		}

	}

	void processChannelOpenRequest(String type, int remoteid, int remotewindow,
			int remotepacket, byte[] requestdata) throws SshException {
		
		ByteArrayWriter response = new ByteArrayWriter();
		
		try {

			if (channelfactories.containsKey(type)) {
				try {
					Ssh2Channel channel = ((ChannelFactory) channelfactories
							.get(type)).createChannel(type, requestdata);

					// Allocate a channel
					// #ifdef DEBUG
					EventLog.LogEvent(this,
							"There are " + this.getChannelCount()
									+ " channels open");
					// #endif

					int localid = allocateChannel(channel);

					if (localid > -1) {
						try {
							channel.init(this, localid);
							byte[] responsedata = channel.create();
							response.write(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
							response.writeInt(remoteid);
							response.writeInt(localid);
							response.writeInt(channel.getWindowSize());
							response.writeInt(channel.getPacketSize());
							if (responsedata != null) {
								response.write(responsedata);

							}

							// #ifdef DEBUG
							EventLog.LogEvent(
									this,
									"Sending SSH_MSG_CHANNEL_OPEN_CONFIRMATION type="
											+ channel.getName() + " id="
											+ channel.getChannelId() + " rid="
											+ remoteid + " window="
											+ channel.getWindowSize()
											+ " packet="
											+ channel.getPacketSize());
							// #endif
							transport.sendMessage(response.toByteArray(), true);

							channel.open(remoteid, remotewindow, remotepacket);

							return;

						} catch (SshException ex) {
							response.write(SSH_MSG_CHANNEL_OPEN_FAILURE);
							response.writeInt(remoteid);
							response.writeInt(ChannelOpenException.CONNECT_FAILED);
							response.writeString(ex.getMessage());
							response.writeString("");
						}

					} else {
						response.write(SSH_MSG_CHANNEL_OPEN_FAILURE);
						response.writeInt(remoteid);
						response.writeInt(ChannelOpenException.RESOURCE_SHORTAGE);
						response.writeString("Maximum allowable open channel limit of "
								+ String.valueOf(maximumChannels())
								+ " exceeded!");
						response.writeString("");
					}

				} catch (ChannelOpenException ex) {
					response.write(SSH_MSG_CHANNEL_OPEN_FAILURE);
					response.writeInt(remoteid);
					response.writeInt(ex.getReason());
					response.writeString(ex.getMessage());
					response.writeString("");
				}
			} else {
				response.write(SSH_MSG_CHANNEL_OPEN_FAILURE);
				response.writeInt(remoteid);
				response.writeInt(ChannelOpenException.UNKNOWN_CHANNEL_TYPE);
				response.writeString(type + " is not a supported channel type!");
				response.writeString("");
			}

			// #ifdef DEBUG
			EventLog.LogEvent(this, "Sending SSH_MSG_CHANNEL_OPEN_FAILURE rid="
					+ remoteid);
			// #endif
			transport.sendMessage(response.toByteArray(), true);
		} catch (IOException ex1) {
			throw new SshException(ex1.getMessage(),
					SshException.INTERNAL_ERROR);
		} finally {
			try {
				response.close();
			} catch (IOException e) {
			}
		}
	}

	void processGlobalRequest(String requestname, boolean wantreply,
			byte[] requestdata) throws SshException {

		ByteArrayWriter response = new ByteArrayWriter();
		try {
			boolean success = false;
			GlobalRequest request = new GlobalRequest(requestname, requestdata);
			if (requesthandlers.containsKey(requestname)) {
				success = ((GlobalRequestHandler) requesthandlers
						.get(requestname)).processGlobalRequest(request);
			}

			if (wantreply) {
				if (success) {
					
					response.write(SSH_MSG_REQUEST_SUCCESS);
					if (request.getData() != null) {
						response.write(request.getData());
					}

					// #ifdef DEBUG
					EventLog.LogEvent(this,
							"Sending SSH_MSG_REQUEST_SUCCESS request="
									+ requestname);
					// #endif
					transport.sendMessage(response.toByteArray(), true);
				} else {
					// Return a response
					transport.sendMessage(
							new byte[] { SSH_MSG_REQUEST_FAILURE }, true);
				}
			}
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				response.close();
			} catch (IOException e) {
			}
		}

	}

	protected void onThreadExit() {
		if (transport!=null && transport.isConnected()) {
			transport.disconnect(TransportProtocol.CONNECTION_LOST, "Exiting");
		}
		stop();
	}

	public void onDisconnect(String msg, int reason) {

	}

	public void onIdle(long lastActivity) {

		SshAbstractChannel[] channels = getActiveChannels();
		for (int i = 0; i < channels.length; i++)
			channels[i].idle();

	}
}
