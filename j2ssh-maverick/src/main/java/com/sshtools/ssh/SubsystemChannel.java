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
package com.sshtools.ssh;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Vector;

/**
 * <p>
 * This class provides useful methods for implementing an SSH2 subsystem.
 * Subsystems typically send messages in the following format. <blockquote>
 * 
 * <pre>
 * UINT           length
 * byte           type
 * byte[length-1] payload
 * </pre>
 * 
 * </blockquote> Messages sent using the methods of this class will have the
 * UINT length automatically added and messages received will be unwrapped with
 * just the type and payload being returned. Although subsystems were defined
 * within the SSH2 connection protocol this class takes a single <a
 * href="SshChannel.html">SshChannel</a> as an argument to its constructor which
 * enables subsystems to run over both SSH1 and SSH2 channels.
 * </p>
 * 
 * @author Lee David Painter
 */
public class SubsystemChannel {

	DataInputStream in;
	DataOutputStream out;
	Vector<Packet> packets = new Vector<Packet>();
	int maximumPacketSize = Integer.parseInt(System.getProperty(
			"maverick.sftp.maxPacketSize", "1024000"));

	protected SshChannel channel;

	/**
	 * Why??? Well using synchronized(in) { } works for all JDK's except 1.2.2
	 * so we need some form of workaround.
	 * 
	 * Synchronized methods seem to work a treat.
	 */
	Reader reader = new Reader();
	Writer writer = new Writer();

	/**
	 * Create a new subsystem channel.
	 * 
	 * @param channel
	 * @throws SshException
	 */
	public SubsystemChannel(SshChannel channel) throws SshException {

		this.channel = channel;

		try {
			in = new DataInputStream(channel.getInputStream());
			out = new DataOutputStream(channel.getOutputStream());
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex.getMessage(),
					SshException.CHANNEL_FAILURE);
		}

	}

	/**
	 * Is the subsystem closed?
	 * 
	 * @return boolean
	 */
	public boolean isClosed() {
		return channel.isClosed();
	}

	/**
	 * Close the subsystem
	 * 
	 * @throws IOException
	 */
	public void close() throws IOException {
		packets.removeAllElements();
		channel.close();
	}

	/**
	 * Read a subsystem message from the channel inputstream. Each
	 * 
	 * @return byte[]
	 * @throws SshException
	 */
	public byte[] nextMessage() throws SshException {
		return reader.readMessage(in);
	}

	/**
	 * Write a subsystem message to the channel outputstream.
	 * 
	 * @param msg
	 * @throws SshException
	 */
	protected void sendMessage(Packet msg) throws SshException {
		writer.sendMessage(msg);
	}

	/**
	 * Send a byte array as a message.
	 * 
	 * @param msg
	 * @throws SshException
	 * @deprecated This has changed internally to use a
	 *             {@link com.sshtools.ssh.Packet} and it is recommended that
	 *             all implementations change to use
	 *             {@link com.sshtools.ssh.Packet}'s as they provide a more
	 *             efficent way of sending data.
	 */
	protected void sendMessage(byte[] msg) throws SshException {
		try {
			Packet pkt = createPacket();
			pkt.write(msg);
			sendMessage(pkt);
		} catch (IOException ex) {
			throw new SshException(SshException.UNEXPECTED_TERMINATION, ex);
		}
	}

	/**
	 * Get a packet from the available pool or create if non available
	 * 
	 * @return Packet
	 * @throws IOException
	 */
	protected Packet createPacket() throws IOException {
		synchronized (packets) {
			if (packets.size() == 0)
				return new Packet();
			Packet p = (Packet) packets.elementAt(0);
			packets.removeElementAt(0);
			return p;
		}
	}

	class Writer {
		synchronized void sendMessage(Packet msg) throws SshException {
			try {
				msg.finish();
				out.write(msg.array(), 0, msg.size());
			} catch (SshIOException ex) {
				throw ex.getRealException();
			} catch (EOFException ex) {
				try {
					close();
				} catch (SshIOException ex1) {
					throw ex1.getRealException();
				} catch (IOException ex1) {
					throw new SshException(ex1.getMessage(),
							SshException.CHANNEL_FAILURE);
				}

				throw new SshException("The channel unexpectedly terminated",
						SshException.CHANNEL_FAILURE);
			} catch (IOException ex) {
				try {
					close();
				} catch (SshIOException ex2) {
					throw ex2.getRealException();
				} catch (IOException ex1) {
					throw new SshException(ex1.getMessage(),
							SshException.CHANNEL_FAILURE);
				}

				throw new SshException("Unknown channel IO failure: "
						+ ex.getMessage(), SshException.CHANNEL_FAILURE);
			} finally {
				msg.reset();
				synchronized (packets) {
					packets.addElement(msg);
				}
			}
		}
	}

	class Reader {
		synchronized byte[] readMessage(DataInputStream in) throws SshException {

			int len = -1;
			try {
				len = in.readInt();

				if (len < 0)
					throw new SshException(
							"Negative message length in SFTP protocol.",
							SshException.PROTOCOL_VIOLATION);

				if (len > maximumPacketSize)
					throw new SshException(
							"Invalid message length in SFTP protocol [" + len
									+ "]", SshException.PROTOCOL_VIOLATION);

				byte[] msg = new byte[len];
				in.readFully(msg);

				return msg;
			} catch (OutOfMemoryError ex) {
				throw new SshException(
						"Invalid message length in SFTP protocol [" + len + "]",
						SshException.PROTOCOL_VIOLATION);
			} catch (EOFException ex) {
				try {
					close();
				} catch (SshIOException ex1) {
					throw ex1.getRealException();
				} catch (IOException ex1) {
					throw new SshException(ex1.getMessage(),
							SshException.CHANNEL_FAILURE);
				}

				throw new SshException("The channel unexpectedly terminated",
						SshException.CHANNEL_FAILURE);
			} catch (IOException ex) {

				if (ex instanceof SshIOException)
					throw ((SshIOException) ex).getRealException();

				try {
					close();
				} catch (SshIOException ex2) {
					throw ex2.getRealException();
				} catch (IOException ex1) {
					throw new SshException(ex1.getMessage(),
							SshException.CHANNEL_FAILURE);
				}

				throw new SshException(SshException.CHANNEL_FAILURE, ex);
			}
		}
	}
}
