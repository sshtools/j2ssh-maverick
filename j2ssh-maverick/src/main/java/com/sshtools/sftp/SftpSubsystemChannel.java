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

package com.sshtools.sftp;

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;
import java.util.Vector;

import com.sshtools.events.Event;
import com.sshtools.events.EventLog;
import com.sshtools.events.EventServiceImplementation;
import com.sshtools.events.J2SSHEventCodes;
import com.sshtools.ssh.Packet;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshIOException;
import com.sshtools.ssh.SshSession;
import com.sshtools.ssh.SubsystemChannel;
import com.sshtools.ssh.message.Message;
import com.sshtools.ssh.message.MessageHolder;
import com.sshtools.util.Base64;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.UnsignedInteger32;
import com.sshtools.util.UnsignedInteger64;

/**
 * This class implements the SFTP protocol which is executed as an SSH
 * subsystem. The basic initialization procedure is as follows: <blockquote>
 * 
 * <pre>
 * // Create an SshClient
 * SshConnector con = SshConnector.getInstance();
 * 
 * // Connect and authenticate an SshClient
 * SshClient ssh = con.connect(....);
 * ....
 * 
 * // Create and initialize an SftpSubsystemChannel
 * SshSession session = ssh.openSessionChannel();
 * if(session instanceof Ssh2Session)
 *    ((Ssh2Session)session).startSubsystem("sftp");
 * 
 * SftpSubsystemChannel sftp = new SftpSubsystemChannel(session);
 * sftp.initialize();
 * </pre>
 * 
 * @author Lee David Painter
 */
public class SftpSubsystemChannel extends SubsystemChannel {

	private String CHARSET_ENCODING = "ISO-8859-1";

	/**
	 * File open flag, opens the file for reading.
	 */
	public static final int OPEN_READ = 0x00000001;

	/**
	 * File open flag, opens the file for writing.
	 */
	public static final int OPEN_WRITE = 0x00000002;

	/**
	 * File open flag, forces all writes to append data at the end of the file.
	 */
	public static final int OPEN_APPEND = 0x00000004;

	/**
	 * File open flag, if specified a new file will be created if one does not
	 * already exist.
	 */
	public static final int OPEN_CREATE = 0x00000008;

	/**
	 * File open flag, forces an existing file with the same name to be
	 * truncated to zero length when creating a file by specifying OPEN_CREATE.
	 */
	public static final int OPEN_TRUNCATE = 0x00000010;

	/**
	 * File open flag, causes an open request to fail if the named file already
	 * exists. OPEN_CREATE must also be specified if this flag is used.
	 */
	public static final int OPEN_EXCLUSIVE = 0x00000020;

	/**
	 * File open flag, causes the file to be opened in text mode. This instructs
	 * the server to convert the text file to the canonical newline convention
	 * in use. Any files retrieved using this mode should then be converted from
	 * the canonical newline convention to that of the clients.
	 */
	public static final int OPEN_TEXT = 0x00000040;

	static final int STATUS_FX_OK = 0;
	static final int STATUS_FX_EOF = 1;

	static final int SSH_FXP_INIT = 1;
	static final int SSH_FXP_VERSION = 2;
	static final int SSH_FXP_OPEN = 3;
	static final int SSH_FXP_CLOSE = 4;
	static final int SSH_FXP_READ = 5;
	static final int SSH_FXP_WRITE = 6;

	static final int SSH_FXP_LSTAT = 7;
	static final int SSH_FXP_FSTAT = 8;
	static final int SSH_FXP_SETSTAT = 9;
	static final int SSH_FXP_FSETSTAT = 10;
	static final int SSH_FXP_OPENDIR = 11;
	static final int SSH_FXP_READDIR = 12;
	static final int SSH_FXP_REMOVE = 13;
	static final int SSH_FXP_MKDIR = 14;
	static final int SSH_FXP_RMDIR = 15;
	static final int SSH_FXP_REALPATH = 16;
	static final int SSH_FXP_STAT = 17;
	static final int SSH_FXP_RENAME = 18;
	static final int SSH_FXP_READLINK = 19;
	static final int SSH_FXP_SYMLINK = 20;

	static final int SSH_FXP_STATUS = 101;
	static final int SSH_FXP_HANDLE = 102;
	static final int SSH_FXP_DATA = 103;
	static final int SSH_FXP_NAME = 104;
	static final int SSH_FXP_ATTRS = 105;

	static final int SSH_FXP_EXTENDED = 200;
	static final int SSH_FXP_EXTENDED_REPLY = 201;

	public static int MAX_VERSION = 4;
	int this_MAX_VERSION = 4;

	int version = -1;
	int serverVersion = -1;

	UnsignedInteger32 requestId = new UnsignedInteger32(0);
	Hashtable<UnsignedInteger32, SftpMessage> responses = new Hashtable<UnsignedInteger32, SftpMessage>();
	SftpThreadSynchronizer sync = new SftpThreadSynchronizer();
	Hashtable<String, byte[]> extensions = new Hashtable<String, byte[]>();

	/**
	 * @throws SshException
	 */
	public SftpSubsystemChannel(SshSession session) throws SshException {
		super(session);
		this.this_MAX_VERSION = MAX_VERSION;
	}

	/**
	 * @throws SshException
	 */
	public SftpSubsystemChannel(SshSession session, int Max_Version)
			throws SshException {
		super(session);
		setThisMaxSftpVersion(Max_Version);
	}

	/**
	 * Sets the maximum SFTP protocol version to use, this should be <=4.
	 * 
	 * @param MAX_VERSION
	 */
	public static void setMaxSftpVersion(int MAX_VERSION) {
		SftpSubsystemChannel.MAX_VERSION = MAX_VERSION;
	}

	/**
	 * Sets the maximum SFTP protocol version to use for this instance, this
	 * should be <=4.
	 * 
	 * @param MAX_VERSION
	 */
	public void setThisMaxSftpVersion(int MAX_VERSION) {
		this.this_MAX_VERSION = MAX_VERSION;
	}

	/**
	 * When called after the <a href="#initialize()">initialize</a> method this
	 * will return the version in operation for this sftp session.
	 * 
	 * @return int
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * Returns the canonical newline convention in use when reading/writing text
	 * files.
	 * 
	 * @return String
	 * @throws SftpStatusException
	 */
	public byte[] getCanonicalNewline() throws SftpStatusException {
		if (version <= 3) {
			throw new SftpStatusException(
					SftpStatusException.SSH_FX_OP_UNSUPPORTED,
					"Newline setting not available for SFTP versions <= 3");

		}

		if (!extensions.containsKey("newline"))
			return "\r\n".getBytes();

		return extensions.get("newline");
	}

	/**
	 * Initializes the sftp subsystem and negotiates a version with the server.
	 * This method must be the first method called after the channel has been
	 * opened. This implementation current supports SFTP protocol version 4 and
	 * below.
	 * 
	 * @throws SshException
	 * @throws UnsupportedEncodingException
	 */
	public void initialize() throws SshException, UnsupportedEncodingException {

		// Initialize the SFTP subsystem
		try {

			Packet packet = createPacket();
			packet.write(SSH_FXP_INIT);
			packet.writeInt(this_MAX_VERSION);

			sendMessage(packet);

			byte[] msg = nextMessage();

			if (msg[0] != SSH_FXP_VERSION) {
				close();
				throw new SshException(
						"Unexpected response from SFTP subsystem.",
						SshException.CHANNEL_FAILURE);
			}

			ByteArrayReader bar = new ByteArrayReader(msg);

			try {
				bar.skip(1);
	
				serverVersion = (int) bar.readInt();
				version = Math.min(serverVersion, MAX_VERSION);
				try {
					while (bar.available() > 0) {
						String name = bar.readString();
						byte[] data = bar.readBinaryString();
	
						extensions.put(name, data);
					}
				} catch (Throwable t) {
				}
			} finally {
				bar.close();
			}

			if (version <= 3)
				setCharsetEncoding("ISO-8859-1");
			else
				setCharsetEncoding("UTF8");
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(SshException.CHANNEL_FAILURE, ex);
		} catch (Throwable t) {
			throw new SshException(SshException.CHANNEL_FAILURE, t);
		}

	}
	
	public void close() throws IOException {
		responses.clear();
		super.close();
	}

	/**
	 * Allows the default character encoding to be overriden for filename
	 * strings. This method should only be called once the channel has been
	 * initialized, if the version of the protocol is less than or equal to 3
	 * the encoding is defaulted to latin1 as no encoding is specified by the
	 * protocol. If the version is greater than 3 the default encoding will be
	 * UTF-8.
	 * 
	 * @param charset
	 * @throws UnsupportedEncodingException
	 * @throws SshException
	 */
	public void setCharsetEncoding(String charset) throws SshException,
			UnsupportedEncodingException {

		if (version == -1)
			throw new SshException(
					"SFTP Channel must be initialized before setting character set encoding",
					SshException.BAD_API_USAGE);

		String test = "123456890";
		test.getBytes(charset);
		CHARSET_ENCODING = charset;
	}

	/**
	 * Version 4 of the SFTP protocol allows the server to return its maximum
	 * supported version instead of the actual version to be used. This method
	 * returns the value provided by the server, if the servers version is less
	 * than or equal to 3 then this method will return the protocol number in
	 * use, otherwise it returns the maximum version supported by the server.
	 * 
	 * @return int
	 */
	public int getServerVersion() {
		return serverVersion;
	}

	/**
	 * Get the current encoding being used for filename Strings.
	 * 
	 * @return String
	 */
	public String getCharsetEncoding() {
		return CHARSET_ENCODING;
	}

	/**
	 * Does the server support an SFTP extension? This checks the extensions
	 * returned by the server during the SFTP version negotiation.
	 * 
	 * @param name
	 *            String
	 * @return boolean
	 */
	public boolean supportsExtension(String name) {
		return extensions.containsKey(name);
	}

	/**
	 * Get the data value of a supported SFTP extension. Call {@link
	 * supportsExtension(String)} before calling this method to determine if the
	 * extension is available.
	 * 
	 * @param name
	 *            String
	 * @return String
	 */
	public byte[] getExtension(String name) {
		return extensions.get(name);
	}

	/**
	 * Send an extension message and return the response. This is for advanced
	 * use only.
	 * 
	 * @param request
	 *            String
	 * @param requestData
	 *            byte[]
	 * @return SftpMessage
	 * @throws SshException
	 * @throws SftpStatusException
	 */
	public SftpMessage sendExtensionMessage(String request, byte[] requestData)
			throws SshException, SftpStatusException {

		try {
			UnsignedInteger32 id = nextRequestId();
			Packet packet = createPacket();
			packet.write(SSH_FXP_EXTENDED);
			packet.writeUINT32(id);
			packet.writeString(request);

			sendMessage(packet);

			return getResponse(id);
		} catch (IOException ex) {
			throw new SshException(SshException.INTERNAL_ERROR, ex);
		}
	}

	/**
	 * Change the permissions of a file.
	 * 
	 * @param file
	 *            the file
	 * @param permissions
	 *            an integer value containing a file permissions mask
	 * @throws SshException
	 *             ,SftpStatusException
	 */
	public void changePermissions(SftpFile file, int permissions)
			throws SftpStatusException, SshException {
		SftpFileAttributes attrs = new SftpFileAttributes(this,
				SftpFileAttributes.SSH_FILEXFER_TYPE_UNKNOWN);
		attrs.setPermissions(new UnsignedInteger32(permissions));
		setAttributes(file, attrs);
	}

	/**
	 * Change the permissions of a file.
	 * 
	 * @param filename
	 *            the path to the file.
	 * @param permissions
	 *            an integer value containing a file permissions mask.
	 * 
	 * @throws SshException
	 *             ,SftpStatusException
	 */
	public void changePermissions(String filename, int permissions)
			throws SftpStatusException, SshException {
		SftpFileAttributes attrs = new SftpFileAttributes(this,
				SftpFileAttributes.SSH_FILEXFER_TYPE_UNKNOWN);
		attrs.setPermissions(new UnsignedInteger32(permissions));
		setAttributes(filename, attrs);
	}

	/**
	 * Change the permissions of a file.
	 * 
	 * @param filename
	 *            the path to the file.
	 * @param permissions
	 *            a string containing the permissions, for example "rw-r--r--"
	 * 
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public void changePermissions(String filename, String permissions)
			throws SftpStatusException, SshException {

		SftpFileAttributes attrs = new SftpFileAttributes(this,
				SftpFileAttributes.SSH_FILEXFER_TYPE_UNKNOWN);
		attrs.setPermissions(permissions);
		setAttributes(filename, attrs);

	}

	/**
	 * Sets the attributes of a file.
	 * 
	 * @param path
	 *            the path to the file.
	 * @param attrs
	 *            the file attributes.
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public void setAttributes(String path, SftpFileAttributes attrs)
			throws SftpStatusException, SshException {
		try {
			UnsignedInteger32 requestId = nextRequestId();

			Packet msg = createPacket();
			msg.write(SSH_FXP_SETSTAT);
			msg.writeInt(requestId.longValue());
			msg.writeString(path, CHARSET_ENCODING);
			msg.write(attrs.toByteArray());

			sendMessage(msg);

			getOKRequestStatus(requestId);
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		}
	}

	/**
	 * Sets the attributes of a file.
	 * 
	 * @param file
	 *            the file object.
	 * @param attrs
	 *            the new attributes.
	 * 
	 * @throws SshException
	 */
	public void setAttributes(SftpFile file, SftpFileAttributes attrs)
			throws SftpStatusException, SshException {
		if (file.getHandle()==null) {
			throw new SftpStatusException(SftpStatusException.INVALID_HANDLE,
					"The handle is not an open file handle!");
		}

		try {
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_FSETSTAT);
			msg.writeInt(requestId.longValue());
			msg.writeBinaryString(file.getHandle());
			msg.write(attrs.toByteArray());

			sendMessage(msg);

			getOKRequestStatus(requestId);
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}
	}

	/**
	 * Send a write request for an open file but do not wait for the response
	 * from the server.
	 * 
	 * @param handle
	 * @param position
	 * @param data
	 * @param off
	 * @param len
	 * @return UnsignedInteger32
	 * @throws SshException
	 */
	public UnsignedInteger32 postWriteRequest(byte[] handle, long position,
			byte[] data, int off, int len) throws SftpStatusException,
			SshException {

		if ((data.length - off) < len) {
			throw new IndexOutOfBoundsException("Incorrect data array size!");
		}

		try {
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_WRITE);
			msg.writeInt(requestId.longValue());
			msg.writeBinaryString(handle);
			msg.writeUINT64(position);
			msg.writeBinaryString(data, off, len);

			sendMessage(msg);

			return requestId;
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}
	}

	/**
	 * Write a block of data to an open file.
	 * 
	 * @param handle
	 *            the open file handle.
	 * @param offset
	 *            the offset in the file to start writing
	 * @param data
	 *            a buffer containing the data to write
	 * @param off
	 *            the offset to start in the buffer
	 * @param len
	 *            the length of data to write (setting to false will increase
	 *            file transfer but may miss errors)
	 * @throws SshException
	 */
	public void writeFile(byte[] handle, UnsignedInteger64 offset, byte[] data,
			int off, int len) throws SftpStatusException, SshException {

		getOKRequestStatus(postWriteRequest(handle, offset.longValue(), data,
				off, len));
	}

	/**
	 * Performs an optimized write of a file through asynchronous messaging and
	 * through buffering the local file into memory.
	 * 
	 * @param handle
	 *            the open file handle to write to
	 * @param blocksize
	 *            the block size to send data, should be between 4096 and 65535
	 * @param outstandingRequests
	 *            the maximum number of requests that can be outstanding at any
	 *            one time
	 * @param in
	 *            the InputStream to read from
	 * @param buffersize
	 *            the size of the temporary buffer to read from the InputStream.
	 *            Data is buffered into a temporary buffer so that the number of
	 *            local filesystem reads is reducted to a minimum. This
	 *            increases performance and so the buffer size should be as high
	 *            as possible. The default operation, if buffersize <= 0 is to
	 *            allocate a buffer the same size as the blocksize, meaning no
	 *            buffer optimization is performed.
	 * @param progress
	 *            provides progress information, may be null.
	 * @throws SshException
	 */
	public void performOptimizedWrite(byte[] handle, int blocksize,
			int outstandingRequests, java.io.InputStream in, int buffersize,
			FileTransferProgress progress) throws SftpStatusException,
			SshException, TransferCancelledException {
		performOptimizedWrite(handle, blocksize, outstandingRequests, in,
				buffersize, progress, 0);
	}

	/**
	 * Performs an optimized write of a file through asynchronous messaging and
	 * through buffering the local file into memory.
	 * 
	 * @param handle
	 *            the open file handle to write to
	 * @param blocksize
	 *            the block size to send data, should be between 4096 and 65535
	 * @param outstandingRequests
	 *            the maximum number of requests that can be outstanding at any
	 *            one time
	 * @param in
	 *            the InputStream to read from
	 * @param buffersize
	 *            the size of the temporary buffer to read from the InputStream.
	 *            Data is buffered into a temporary buffer so that the number of
	 *            local filesystem reads is reducted to a minimum. This
	 *            increases performance and so the buffer size should be as high
	 *            as possible. The default operation, if buffersize <= 0 is to
	 *            allocate a buffer the same size as the blocksize, meaning no
	 *            buffer optimization is performed.
	 * @param progress
	 *            provides progress information, may be null.
	 * @param position
	 *            the position in the file to start writing to.
	 * @throws SshException
	 */
	public void performOptimizedWrite(byte[] handle, int blocksize,
			int outstandingRequests, java.io.InputStream in, int buffersize,
			FileTransferProgress progress, long position)
			throws SftpStatusException, SshException,
			TransferCancelledException {

		try {
			if (blocksize < 4096) {
				throw new SshException("Block size cannot be less than 4096",
						SshException.BAD_API_USAGE);
			}

			if (position < 0)
				throw new SshException(
						"Position value must be greater than zero!",
						SshException.BAD_API_USAGE);

			if (position > 0) {
				if (progress != null)
					progress.progressed(position);
			}

			if (buffersize <= 0) {
				buffersize = blocksize;
			}

			byte[] buf = new byte[blocksize];

			long transfered = position;
			int buffered = 0;

			Vector<UnsignedInteger32> requests = new Vector<UnsignedInteger32>();

			in = new java.io.BufferedInputStream(in, buffersize);

			UnsignedInteger32 requestId;

			while (true) {

				buffered = in.read(buf);
				if (buffered == -1)
					break;

				requests.addElement(postWriteRequest(handle, transfered, buf,
						0, buffered));

				transfered += buffered;

				if (progress != null) {

					if (progress.isCancelled())
						throw new TransferCancelledException();

					progress.progressed(transfered);
				}

				if (requests.size() > outstandingRequests) {
					requestId = (UnsignedInteger32) requests.elementAt(0);
					requests.removeElementAt(0);
					getOKRequestStatus(requestId);
				}

			}

			for (Enumeration<UnsignedInteger32> e = requests.elements(); e.hasMoreElements();) {
				getOKRequestStatus(e.nextElement());
			}

			requests.removeAllElements();
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (EOFException ex) {
			// The channel has reached EOF before the transfer could complete so
			// make sure the channel is closed and throw a status exception
			try {
				close();
			} catch (SshIOException ex1) {
				throw ex1.getRealException();
			} catch (IOException ex1) {
				throw new SshException(ex1.getMessage(),
						SshException.CHANNEL_FAILURE);
			}

			throw new SftpStatusException(
					SftpStatusException.SSH_FX_CONNECTION_LOST,
					"The SFTP channel terminated unexpectedly");
		} catch (IOException ex) {
			throw new SshException(ex);
		} catch (OutOfMemoryError ex) {
			throw new SshException(
					"Resource Shortage: try reducing the local file buffer size",
					SshException.BAD_API_USAGE);
		}

	}

	/**
	 * Performs an optimized read of a file through use of asynchronous
	 * messages. The total number of outstanding read requests is configurable.
	 * This should be safe on file objects as the SSH protocol states that file
	 * read operations should return the exact number of bytes requested in each
	 * request. However the server is not required to return the exact number of
	 * bytes on device files and so this method should not be used for device
	 * files.
	 * 
	 * @param handle
	 *            the open files handle
	 * @param length
	 *            the length of the file
	 * @param blocksize
	 *            the blocksize to read
	 * @param out
	 *            an OutputStream to output the file into
	 * @param outstandingRequests
	 *            the maximum number of read requests to
	 * @param progress
	 * @throws SshException
	 */
	public void performOptimizedRead(byte[] handle, long length, int blocksize,
			java.io.OutputStream out, int outstandingRequests,
			FileTransferProgress progress) throws SftpStatusException,
			SshException, TransferCancelledException {

		performOptimizedRead(handle, length, blocksize, out,
				outstandingRequests, progress, 0);
	}

	/**
	 * Performs an optimized read of a file through use of asynchronous
	 * messages. The total number of outstanding read requests is configurable.
	 * This should be safe on file objects as the SSH protocol states that file
	 * read operations should return the exact number of bytes requested in each
	 * request. However the server is not required to return the exact number of
	 * bytes on device files and so this method should not be used for device
	 * files.
	 * 
	 * @param handle
	 *            the open files handle
	 * @param length
	 *            the amount of the file file to be read, equal to the file
	 *            length when reading the whole file
	 * @param blocksize
	 *            the blocksize to read
	 * @param out
	 *            an OutputStream to output the file into
	 * @param outstandingRequests
	 *            the maximum number of read requests to
	 * @param progress
	 * @param position
	 *            the postition from which to start reading the file
	 * @throws SshException
	 */
	public void performOptimizedRead(byte[] handle, long length, int blocksize,
			OutputStream out, int outstandingRequests,
			FileTransferProgress progress, long position)
			throws SftpStatusException, SshException,
			TransferCancelledException {

		// #ifdef DEBUG
		EventLog.LogEvent(this, "Performing optimized read length=" + length
				+ " postion=" + position + " blocksize=" + blocksize
				+ " outstandingRequests=" + outstandingRequests);
		// #endif

		if (length <= 0) {
			// We cannot perform an optimised read on this file since we don't
			// know its length so
			// here we assume its very large
			length = Long.MAX_VALUE;
		}

		try {
			if (blocksize < 1 || blocksize > 32768) {
				// #ifdef DEBUG
				EventLog.LogEvent(this,
						"Blocksize to large for some SFTP servers, reseting to 32K");
				// #endif
				blocksize = 32768;
			}

			/**
			 * LDP - Obtain the first block using a synchronous call. We do this
			 * to determine if the server is conforming to the spec and
			 * returning as much data as we have asked for. If not we
			 * reconfigure the block size to the number of bytes returned.
			 */

			if (position < 0) {
				throw new SshException(
						"Position value must be greater than zero!",
						SshException.BAD_API_USAGE);
			}

			byte[] tmp = new byte[blocksize];

			int i = readFile(handle, new UnsignedInteger64(0), tmp, 0,
					tmp.length);

			// if i=-1 then eof so return, maybe should throw exception on null
			// files?
			if (i == -1) {
				return;
			}
			// if the first block contains required data, write to the output
			// buffer,
			// write the portion of tmp needed to out
			// change position
			if (i > position) {
				out.write(tmp, (int) position, (int) (i - position));
				length = length - (i - position);
				position = i;
			}

			// if the first block contains the whole portion of the file to be
			// read, then return
			if ((position + length) <= i) {
				return;
			}

			// reconfigure the blocksize if necessary
			if (i < blocksize && length > i) {
				blocksize = i;
			}

			tmp = null;

			long numBlocks = length / blocksize;
			long osr = outstandingRequests;

			if (position > 0) {
				if (progress != null)
					progress.progressed(position);
			}

			Vector<UnsignedInteger32> requests = new Vector<UnsignedInteger32>(outstandingRequests);
			long offset = position;

			if (numBlocks < osr) {
				osr = numBlocks + 1;
			}

			if (osr <= 0) {
				// #ifdef DEBUG
				EventLog.LogEvent(this,
						"We calculated zero outstanding requests! numBlocks="
								+ numBlocks + " outstandingRequests="
								+ outstandingRequests + " blocksize="
								+ blocksize + " length=" + length
								+ " position=" + position);
				// #endif
				osr = 1; // We need at least one or there will be trouble.
			}

			long expected = numBlocks + 2;
			int completed = 0;
			long transfered = position;

			// Fire an initial round of requests
			for (i = 0; i < osr; i++) {
				// #ifdef DEBUG
				EventLog.LogEvent(this, "Posting request for file offset "
						+ offset);
				// #endif
				requests.addElement(postReadRequest(handle, offset, blocksize));
				offset += blocksize;

				if (progress != null && progress.isCancelled()) {
					throw new TransferCancelledException();
				}
			}

			UnsignedInteger32 requestId;
			int dataLen;
			while (true) {
				requestId = (UnsignedInteger32) requests.elementAt(0);
				requests.removeElementAt(0);
				SftpMessage bar = getResponse(requestId);
				if (bar.getType() == SSH_FXP_DATA) {
					dataLen = (int)bar.readInt();
					//tmp = bar.readBinaryString();
					// #ifdef DEBUG
					EventLog.LogEvent(this, "Get " + dataLen
							+ " bytes of data");
					// #endif
					out.write(bar.array(), bar.getPosition(), dataLen);
					completed++;
					bar.dispose();
					if (progress != null) {
						progress.progressed(transfered += dataLen);
					}
				} else if (bar.getType() == SSH_FXP_STATUS) {
					int status = (int) bar.readInt();
					if (status == SftpStatusException.SSH_FX_EOF) {
						// #ifdef DEBUG
						EventLog.LogEvent(this, "Received file EOF");
						// #endif
						return;
					}
					if (version >= 3) {
						String desc = bar.readString().trim();
						// #ifdef DEBUG
						EventLog.LogEvent(this, "Received status " + desc);
						// #endif
						throw new SftpStatusException(status, desc);
					}
					// #ifdef DEBUG
					EventLog.LogEvent(this, "Received status " + status);
					// #endif
					throw new SftpStatusException(status);
				} else {
					close();
					throw new SshException(
							"The server responded with an unexpected message",
							SshException.CHANNEL_FAILURE);
				}
				/**
				 * If the file length is incorrect we could be stuck in an
				 * endless loop so we check for an empty request list. This
				 * could only happen if the file length is incorrect.
				 */
				if (requests.isEmpty()
						|| completed + requests.size() < expected) {
					// #ifdef DEBUG
					EventLog.LogEvent(this, "Posting request for file offset "
							+ offset);
					// #endif
					requests.addElement(postReadRequest(handle, offset,
							blocksize));
					offset += blocksize;
				}
				if (progress != null && progress.isCancelled()) {
					throw new TransferCancelledException();
				}
			}
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (EOFException ex) {
			// #ifdef DEBUG
			EventLog.LogEvent(this, "Channel has reached EOF", ex);
			// #endif
			// The channel has reached EOF before the transfer could complete so
			// make sure the channel is closed and throw a status exception
			try {
				close();
			} catch (SshIOException ex1) {
				throw ex1.getRealException();
			} catch (IOException ex1) {
				throw new SshException(ex1.getMessage(),
						SshException.CHANNEL_FAILURE);
			}

			throw new SftpStatusException(
					SftpStatusException.SSH_FX_CONNECTION_LOST,
					"The SFTP channel terminated unexpectedly");
		} catch (IOException ex) {
			throw new SshException(ex);
		}

	}

	/**
	 * Perform a synchronous read of a file from the remote file system. This
	 * implementation waits for acknowledgement of every data packet before
	 * requesting additional data.
	 * 
	 * @param handle
	 * @param blocksize
	 * @param out
	 * @param progress
	 * @param position
	 * @throws SftpStatusException
	 * @throws SshException
	 * @throws TransferCancelledException
	 */
	public void performSynchronousRead(byte[] handle, int blocksize,
			OutputStream out, FileTransferProgress progress, long position)
			throws SftpStatusException, SshException,
			TransferCancelledException {

		// #ifdef DEBUG
		EventLog.LogEvent(this, "Performing synchronous read postion="
				+ position + " blocksize=" + blocksize);
		// #endif

		if (blocksize < 1 || blocksize > 32768) {
			// #ifdef DEBUG
			EventLog.LogEvent(this,
					"Blocksize to large for some SFTP servers, reseting to 32K");
			// #endif
			blocksize = 32768;
		}

		if (position < 0) {
			throw new SshException("Position value must be greater than zero!",
					SshException.BAD_API_USAGE);
		}

		byte[] tmp = new byte[blocksize];

		int read;
		UnsignedInteger64 offset = new UnsignedInteger64(position);

		if (position > 0) {
			if (progress != null)
				progress.progressed(position);
		}

		try {
			while ((read = readFile(handle, offset, tmp, 0, tmp.length)) > -1) {
				if (progress != null && progress.isCancelled()) {
					throw new TransferCancelledException();
				}
				out.write(tmp, 0, read);
				offset = UnsignedInteger64.add(offset, read);
				if (progress != null)
					progress.progressed(offset.longValue());
			}
		} catch (IOException e) {
			throw new SshException(e);
		}
	}

	/**
	 * Post a read request to the server and return the request id; this is used
	 * to optimize file downloads. In normal operation the files are transfered
	 * by using a synchronous set of requests, however this slows the download
	 * as the client has to wait for the servers response before sending another
	 * request.
	 * 
	 * @param handle
	 * @param offset
	 * @param len
	 * @return UnsignedInteger32
	 * @throws SshException
	 */
	public UnsignedInteger32 postReadRequest(byte[] handle, long offset, int len)
			throws SftpStatusException, SshException {
		try {
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_READ);
			msg.writeInt(requestId.longValue());
			msg.writeBinaryString(handle);
			msg.writeUINT64(offset);
			msg.writeInt(len);

			sendMessage(msg);

			return requestId;
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}

	}

	/**
	 * Read a block of data from an open file.
	 * 
	 * @param handle
	 *            the open file handle
	 * @param offset
	 *            the offset to start reading in the file
	 * @param output
	 *            a buffer to write the returned data to
	 * @param off
	 *            the starting offset in the output buffer
	 * @param len
	 *            the length of data to read
	 * @return int
	 * @throws SshException
	 */
	public int readFile(byte[] handle, UnsignedInteger64 offset, byte[] output,
			int off, int len) throws SftpStatusException, SshException {

		try {
			if ((output.length - off) < len) {
				throw new IndexOutOfBoundsException(
						"Output array size is smaller than read length!");
			}

			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_READ);
			msg.writeInt(requestId.longValue());
			msg.writeBinaryString(handle);
			msg.write(offset.toByteArray());
			msg.writeInt(len);

			sendMessage(msg);

			SftpMessage bar = getResponse(requestId);

			if (bar.getType() == SSH_FXP_DATA) {
				byte[] msgdata = bar.readBinaryString();
				System.arraycopy(msgdata, 0, output, off, msgdata.length);
				return msgdata.length;
			} else if (bar.getType() == SSH_FXP_STATUS) {
				int status = (int) bar.readInt();
				if (status == SftpStatusException.SSH_FX_EOF)
					return -1;
				if (version >= 3) {
					String desc = bar.readString().trim();
					throw new SftpStatusException(status, desc);
				}
				throw new SftpStatusException(status);
			} else {
				close();
				throw new SshException(
						"The server responded with an unexpected message",
						SshException.CHANNEL_FAILURE);
			}
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}

	}

	/**
	 * Utility method to obtain an {@link SftpFile} instance for a given path.
	 * 
	 * @param path
	 * @return SftpFile
	 * @throws SftpStatusException
	 * @throws SshException
	 */
	public SftpFile getFile(String path) throws SftpStatusException,
			SshException {
		String absolute = getAbsolutePath(path);
		SftpFile file = new SftpFile(absolute, getAttributes(absolute));
		file.sftp = this;
		return file;
	}

	/**
	 * Get the absolute path of a file.
	 * 
	 * @param file
	 * @return String
	 * @throws SshException
	 */
	public String getAbsolutePath(SftpFile file) throws SftpStatusException,
			SshException {
		return getAbsolutePath(file.getFilename());
	}

	/**
	 * Create a symbolic link.
	 * 
	 * @param targetpath
	 *            the symbolic link to create
	 * @param linkpath
	 *            the path to which the symbolic link points
	 * @throws SshException
	 *             if the remote SFTP version is < 3 an exception is thrown as
	 *             this feature is not supported by previous versions of the
	 *             protocol.
	 */
	public void createSymbolicLink(String targetpath, String linkpath)
			throws SftpStatusException, SshException {

		if (version < 3) {
			throw new SftpStatusException(
					SftpStatusException.SSH_FX_OP_UNSUPPORTED,
					"Symbolic links are not supported by the server SFTP version "
							+ String.valueOf(version));
		}
		try {
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_SYMLINK);
			msg.writeInt(requestId.longValue());
			msg.writeString(linkpath, CHARSET_ENCODING);
			msg.writeString(targetpath, CHARSET_ENCODING);

			sendMessage(msg);

			getOKRequestStatus(requestId);
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}

	}

	/**
	 * Get the target path of a symbolic link.
	 * 
	 * @param linkpath
	 * @return String
	 * @throws SshException
	 *             if the remote SFTP version is < 3 an exception is thrown as
	 *             this feature is not supported by previous versions of the
	 *             protocol.
	 */
	public String getSymbolicLinkTarget(String linkpath)
			throws SftpStatusException, SshException {

		if (version < 3) {
			throw new SftpStatusException(
					SftpStatusException.SSH_FX_OP_UNSUPPORTED,
					"Symbolic links are not supported by the server SFTP version "
							+ String.valueOf(version));
		}

		try {
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_READLINK);
			msg.writeInt(requestId.longValue());
			msg.writeString(linkpath, CHARSET_ENCODING);

			sendMessage(msg);

			SftpFile[] files = extractFiles(getResponse(requestId), null);
			return files[0].getAbsolutePath();
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}

	}

	/**
	 * Gets the users default directory.
	 * 
	 * @return String
	 * @throws SshException
	 */
	public String getDefaultDirectory() throws SftpStatusException,
			SshException {
		return getAbsolutePath("");
	}

	/**
	 * Get the absolute path of a file.
	 * 
	 * @param path
	 * @return String
	 * @throws SshException
	 */
	public String getAbsolutePath(String path) throws SftpStatusException,
			SshException {
		try {
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_REALPATH);
			msg.writeInt(requestId.longValue());
			msg.writeString(path, CHARSET_ENCODING);
			sendMessage(msg);

			SftpMessage bar = getResponse(requestId);
			if (bar.getType() == SSH_FXP_NAME) {
				SftpFile[] files = extractFiles(bar, null);

				if (files.length != 1) {
					close();
					throw new SshException(
							"Server responded to SSH_FXP_REALPATH with too many files!",
							SshException.CHANNEL_FAILURE);
				}

				return files[0].getAbsolutePath();
			} else if (bar.getType() == SSH_FXP_STATUS) {
				int status = (int) bar.readInt();
				if (version >= 3) {
					String desc = bar.readString().trim();
					throw new SftpStatusException(status, desc);
				}
				throw new SftpStatusException(status);
			} else {
				close();
				throw new SshException(
						"The server responded with an unexpected message",
						SshException.CHANNEL_FAILURE);
			}
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}

	}

	/**
	 * <p>
	 * List the children of a directory.
	 * </p>
	 * <p>
	 * To use this method first open a directory with the <a
	 * href="#openDirectory(java.lang.String)"> openDirectory</a> method and
	 * then create a Vector to store the results. To retrieve the results keep
	 * calling this method until it returns -1 which indicates no more results
	 * will be returned. <blockquote>
	 * 
	 * <pre>
	 * SftpFile dir = sftp.openDirectory(&quot;code/foobar&quot;);
	 * Vector results = new Vector();
	 * while (sftp.listChildren(dir, results) &gt; -1)
	 * 	;
	 * sftp.closeFile(dir);
	 * </pre>
	 * 
	 * </blockquote>
	 * 
	 * </p>
	 * 
	 * @param file
	 * @param children
	 * @return int
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public int listChildren(SftpFile file, Vector<SftpFile> children)
			throws SftpStatusException, SshException {
		if (file.isDirectory()) {
			if (file.getHandle()==null) {
				file = openDirectory(file.getAbsolutePath());
				if (file.getHandle()==null) {
					throw new SftpStatusException(
							SftpStatusException.SSH_FX_FAILURE,
							"Failed to open directory");
				}
			}
		} else {
			throw new SshException("Cannot list children for this file object",
					SshException.BAD_API_USAGE);
		}

		try {
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_READDIR);
			msg.writeInt(requestId.longValue());
			msg.writeBinaryString(file.getHandle());

			sendMessage(msg);
			;

			SftpMessage bar = getResponse(requestId);
			if (bar.getType() == SSH_FXP_NAME) {
				SftpFile[] files = extractFiles(bar, file.getAbsolutePath());

				for (int i = 0; i < files.length; i++) {
					children.addElement(files[i]);
				}
				return files.length;
			} else if (bar.getType() == SSH_FXP_STATUS) {
				int status = (int) bar.readInt();

				if (status == SftpStatusException.SSH_FX_EOF) {
					return -1;
				}

				if (version >= 3) {
					String desc = bar.readString().trim();
					throw new SftpStatusException(status, desc);
				}
				throw new SftpStatusException(status);

			} else {
				close();
				throw new SshException(
						"The server responded with an unexpected message",
						SshException.CHANNEL_FAILURE);
			}
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}

	}

	SftpFile[] extractFiles(SftpMessage bar, String parent) throws SshException {

		try {

			if (parent != null && !parent.endsWith("/")) {
				parent += "/";
			}

			int count = (int) bar.readInt();
			SftpFile[] files = new SftpFile[count];

			String shortname;
			String longname = null;

			for (int i = 0; i < files.length; i++) {
				shortname = bar.readString(CHARSET_ENCODING);

				if (version <= 3) {
					// read and throw away the longname as don't use it but need
					// to read it out of the bar to advance the position.
					longname = bar.readString(CHARSET_ENCODING);
				}

				files[i] = new SftpFile(parent != null ? parent + shortname
						: shortname, new SftpFileAttributes(this, bar));
				files[i].longname = longname;

				// Work out username/group from long name
				if (longname != null && version <= 3) {
					try {
						StringTokenizer t = new StringTokenizer(longname);
						t.nextToken();
						t.nextToken();
						String username = t.nextToken();
						String group = t.nextToken();

						files[i].getAttributes().setUsername(username);
						files[i].getAttributes().setGroup(group);

					} catch (Exception e) {

					}

				}

				files[i].setSFTPSubsystem(this);
			}

			return files;
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}
	}

	/**
	 * Recurse through a hierarchy of directories creating them as necessary.
	 * 
	 * @param path
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public void recurseMakeDirectory(String path) throws SftpStatusException,
			SshException {
		SftpFile file;

		if (path.trim().length() > 0) {
			try {
				file = openDirectory(path);
				file.close();
			} catch (SshException ioe) {

				int idx = 0;

				do {

					idx = path.indexOf('/', idx);
					String tmp = (idx > -1 ? path.substring(0, idx + 1) : path);
					try {
						file = openDirectory(tmp);
						file.close();
					} catch (SshException ioe7) {
						makeDirectory(tmp);
					}

				} while (idx > -1);

			}
		}
	}

	/**
	 * Open a file.
	 * 
	 * @param absolutePath
	 * @param flags
	 * @return SftpFile
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public SftpFile openFile(String absolutePath, int flags)
			throws SftpStatusException, SshException {
		return openFile(absolutePath, flags, new SftpFileAttributes(this,
				SftpFileAttributes.SSH_FILEXFER_TYPE_UNKNOWN));
	}

	/**
	 * Open a file.
	 * 
	 * @param absolutePath
	 * @param flags
	 * @param attrs
	 * @return SftpFile
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public SftpFile openFile(String absolutePath, int flags,
			SftpFileAttributes attrs) throws SftpStatusException, SshException {
		if (attrs == null) {
			attrs = new SftpFileAttributes(this,
					SftpFileAttributes.SSH_FILEXFER_TYPE_UNKNOWN);
		}

		try {
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_OPEN);
			msg.writeInt(requestId.longValue());
			msg.writeString(absolutePath, CHARSET_ENCODING);
			msg.writeInt(flags);
			msg.write(attrs.toByteArray());

			sendMessage(msg);

			byte[] handle = getHandleResponse(requestId);

			SftpFile file = new SftpFile(absolutePath, null);
			file.setHandle(handle);
			file.setSFTPSubsystem(this);

			EventServiceImplementation.getInstance().fireEvent(
					(new Event(this, J2SSHEventCodes.EVENT_SFTP_FILE_OPENED,
							true)).addAttribute(
							J2SSHEventCodes.ATTRIBUTE_FILE_NAME,
							file.getAbsolutePath()));
			return file;
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}
	}

	@SuppressWarnings("unused")
	private String getSafeHandle(byte[] handle) {
		return Base64.encodeBytes(handle, 0, handle.length, true);
	}
	
	@SuppressWarnings("unused")
	private byte[] getSafeHandle(String handle) {
		return Base64.decode(handle);
	}
	/**
	 * Open a directory.
	 * 
	 * @param path
	 * @return sftpfile
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public SftpFile openDirectory(String path) throws SftpStatusException,
			SshException {

		String absolutePath = getAbsolutePath(path);

		SftpFileAttributes attrs = getAttributes(absolutePath);

		if (!attrs.isDirectory()) {
			throw new SftpStatusException(SftpStatusException.SSH_FX_FAILURE,
					path + " is not a directory");
		}

		try {
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_OPENDIR);
			msg.writeInt(requestId.longValue());
			msg.writeString(path, CHARSET_ENCODING);
			sendMessage(msg);

			byte[] handle = getHandleResponse(requestId);

			SftpFile file = new SftpFile(absolutePath, attrs);
			file.setHandle(handle);
			file.setSFTPSubsystem(this);

			return file;
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}

	}

	void closeHandle(byte[] handle) throws SftpStatusException, SshException {
		try {
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_CLOSE);
			msg.writeInt(requestId.longValue());
			msg.writeBinaryString(handle);

			sendMessage(msg);

			getOKRequestStatus(requestId);
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}
	}

	/**
	 * Close a file or directory.
	 * 
	 * @param file
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public void closeFile(SftpFile file) throws SftpStatusException,
			SshException {

		if (file.getHandle() != null) {
			closeHandle(file.getHandle());
			EventServiceImplementation.getInstance().fireEvent(
					(new Event(this, J2SSHEventCodes.EVENT_SFTP_FILE_CLOSED,
							true)).addAttribute(
							J2SSHEventCodes.ATTRIBUTE_FILE_NAME,
							file.getAbsolutePath()));
			file.setHandle(null);
		}
	}


	/**
	 * Remove an empty directory.
	 * 
	 * @param path
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public void removeDirectory(String path) throws SftpStatusException,
			SshException {
		try {
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_RMDIR);
			msg.writeInt(requestId.longValue());
			msg.writeString(path, CHARSET_ENCODING);

			sendMessage(msg);

			getOKRequestStatus(requestId);
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}
		EventServiceImplementation.getInstance().fireEvent(
				(new Event(this, J2SSHEventCodes.EVENT_SFTP_DIRECTORY_DELETED,
						true)).addAttribute(
						J2SSHEventCodes.ATTRIBUTE_DIRECTORY_PATH, path));
	}

	/**
	 * Remove a file.
	 * 
	 * @param filename
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public void removeFile(String filename) throws SftpStatusException,
			SshException {
		try {
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_REMOVE);
			msg.writeInt(requestId.longValue());
			msg.writeString(filename, CHARSET_ENCODING);

			sendMessage(msg);

			getOKRequestStatus(requestId);
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}
		EventServiceImplementation.getInstance()
				.fireEvent(
						(new Event(this,
								J2SSHEventCodes.EVENT_SFTP_FILE_DELETED, true))
								.addAttribute(
										J2SSHEventCodes.ATTRIBUTE_FILE_NAME,
										filename));
	}

	/**
	 * Rename an existing file.
	 * 
	 * @param oldpath
	 * @param newpath
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public void renameFile(String oldpath, String newpath)
			throws SftpStatusException, SshException {

		if (version < 2) {
			throw new SftpStatusException(
					SftpStatusException.SSH_FX_OP_UNSUPPORTED,
					"Renaming files is not supported by the server SFTP version "
							+ String.valueOf(version));
		}
		try {
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_RENAME);
			msg.writeInt(requestId.longValue());
			msg.writeString(oldpath, CHARSET_ENCODING);
			msg.writeString(newpath, CHARSET_ENCODING);

			sendMessage(msg);

			getOKRequestStatus(requestId);
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}
		EventServiceImplementation
				.getInstance()
				.fireEvent(
						(new Event(this,
								J2SSHEventCodes.EVENT_SFTP_FILE_RENAMED, true))
								.addAttribute(
										J2SSHEventCodes.ATTRIBUTE_FILE_NAME,
										oldpath)
								.addAttribute(
										J2SSHEventCodes.ATTRIBUTE_FILE_NEW_NAME,
										newpath));
	}

	/**
	 * Get the attributes of a file. This method follows symbolic links
	 * 
	 * @param path
	 * @return SftpFileAttributes
	 * @throws SshException
	 */
	public SftpFileAttributes getAttributes(String path)
			throws SftpStatusException, SshException {
		return getAttributes(path, SSH_FXP_STAT);
	}

	/**
	 * Get the attributes of a file. This method does not follow symbolic links
	 * so will return the attributes of an actual link, not its target. 
	 * 
	 * @param path
	 * @return
	 * @throws SftpStatusException
	 * @throws SshException
	 */
	public SftpFileAttributes getLinkAttributes(String path)
			throws SftpStatusException, SshException {
		return getAttributes(path, SSH_FXP_LSTAT);
	}
	
	protected SftpFileAttributes getAttributes(String path, int messageId)
			throws SftpStatusException, SshException {
		try {
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(messageId);
			msg.writeInt(requestId.longValue());
			msg.writeString(path, CHARSET_ENCODING);

			if (version > 3) {
				msg.writeInt(SftpFileAttributes.SSH_FILEXFER_ATTR_SIZE
						| SftpFileAttributes.SSH_FILEXFER_ATTR_PERMISSIONS
						| SftpFileAttributes.SSH_FILEXFER_ATTR_ACCESSTIME
						| SftpFileAttributes.SSH_FILEXFER_ATTR_CREATETIME
						| SftpFileAttributes.SSH_FILEXFER_ATTR_MODIFYTIME
						| SftpFileAttributes.SSH_FILEXFER_ATTR_ACL
						| SftpFileAttributes.SSH_FILEXFER_ATTR_OWNERGROUP
						| SftpFileAttributes.SSH_FILEXFER_ATTR_SUBSECOND_TIMES
						| SftpFileAttributes.SSH_FILEXFER_ATTR_EXTENDED);
			}

			sendMessage(msg);

			SftpMessage bar = getResponse(requestId);

			return extractAttributes(bar);
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}
	}

	SftpFileAttributes extractAttributes(SftpMessage bar)
			throws SftpStatusException, SshException {
		try {
			if (bar.getType() == SSH_FXP_ATTRS) {
				return new SftpFileAttributes(this, bar);
			} else if (bar.getType() == SSH_FXP_STATUS) {
				int status = (int) bar.readInt();

				// Only read the message string if the version is >= 3
				if (version >= 3) {
					String msg = bar.readString().trim();
					throw new SftpStatusException(status, msg);
				}
				throw new SftpStatusException(status);
			} else {
				close();
				throw new SshException(
						"The server responded with an unexpected message.",
						SshException.CHANNEL_FAILURE);
			}
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}
	}

	/**
	 * Get the attributes of a file.
	 * 
	 * @param file
	 * @return SftpFileAttributes
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public SftpFileAttributes getAttributes(SftpFile file)
			throws SftpStatusException, SshException {

		try {
			if (file.getHandle()==null) {
				return getAttributes(file.getAbsolutePath());
			}
			UnsignedInteger32 requestId = nextRequestId();
			Packet msg = createPacket();
			msg.write(SSH_FXP_FSTAT);
			msg.writeInt(requestId.longValue());
			msg.writeBinaryString(file.getHandle());
			if (version > 3) {
				msg.writeInt(SftpFileAttributes.SSH_FILEXFER_ATTR_SIZE
						| SftpFileAttributes.SSH_FILEXFER_ATTR_PERMISSIONS
						| SftpFileAttributes.SSH_FILEXFER_ATTR_ACCESSTIME
						| SftpFileAttributes.SSH_FILEXFER_ATTR_CREATETIME
						| SftpFileAttributes.SSH_FILEXFER_ATTR_MODIFYTIME
						| SftpFileAttributes.SSH_FILEXFER_ATTR_ACL
						| SftpFileAttributes.SSH_FILEXFER_ATTR_OWNERGROUP
						| SftpFileAttributes.SSH_FILEXFER_ATTR_SUBSECOND_TIMES
						| SftpFileAttributes.SSH_FILEXFER_ATTR_EXTENDED);
			}
			sendMessage(msg);

			return extractAttributes(getResponse(requestId));
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}

	}

	/**
	 * Make a directory. If the directory exists this method will throw an
	 * exception.
	 * 
	 * @param path
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public void makeDirectory(String path) throws SftpStatusException,
			SshException {
		makeDirectory(path, new SftpFileAttributes(this,
				SftpFileAttributes.SSH_FILEXFER_TYPE_DIRECTORY));
	}

	/**
	 * Make a directory. If the directory exists this method will throw an
	 * exception.
	 * 
	 * @param path
	 * @param attrs
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public void makeDirectory(String path, SftpFileAttributes attrs)
			throws SftpStatusException, SshException {
		try {
			UnsignedInteger32 requestId = nextRequestId();

			Packet msg = createPacket();
			msg.write(SSH_FXP_MKDIR);
			msg.writeInt(requestId.longValue());
			msg.writeString(path, CHARSET_ENCODING);
			msg.write(attrs.toByteArray());

			sendMessage(msg);

			getOKRequestStatus(requestId);
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}
	}

	byte[] getHandleResponse(UnsignedInteger32 requestId)
			throws SftpStatusException, SshException {

		try {
			SftpMessage bar = getResponse(requestId);
			if (bar.getType() == SSH_FXP_HANDLE) {
				return bar.readBinaryString();
			} else if (bar.getType() == SSH_FXP_STATUS) {
				int status = (int) bar.readInt();

				if (version >= 3) {
					String msg = bar.readString().trim();
					throw new SftpStatusException(status, msg);
				}
				throw new SftpStatusException(status);
			} else {
				close();
				throw new SshException(
						"The server responded with an unexpected message!",
						SshException.CHANNEL_FAILURE);
			}
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}
	}

	/**
	 * Verify that an OK status has been returned for a request id.
	 * 
	 * @param requestId
	 * @throws SftpStatusException
	 *             , SshException
	 */
	public void getOKRequestStatus(UnsignedInteger32 requestId)
			throws SftpStatusException, SshException {

		try {
			SftpMessage bar = getResponse(requestId);
			if (bar.getType() == SSH_FXP_STATUS) {
				int status = (int) bar.readInt();
				if (status == SftpStatusException.SSH_FX_OK) {
					return;
				}

				if (version >= 3) {
					String msg = bar.readString().trim();
					throw new SftpStatusException(status, msg);
				}
				throw new SftpStatusException(status);

			}
			close();
			throw new SshException(
					"The server responded with an unexpected message!",
					SshException.CHANNEL_FAILURE);
		} catch (SshIOException ex) {
			throw ex.getRealException();
		} catch (IOException ex) {
			throw new SshException(ex);
		}

	}

	SftpMessage getResponse(UnsignedInteger32 requestId) throws SshException {

		SftpMessage msg;
		MessageHolder holder = new MessageHolder();
		while (holder.msg == null) {
			try {
				// Read the next response message
				if (sync.requestBlock(requestId, holder)) {
					msg = new SftpMessage(nextMessage());
					responses.put(new UnsignedInteger32(msg.getMessageId()),
							msg);
				}
			} catch (InterruptedException e) {
				try {
					close();
				} catch (SshIOException ex) {
					throw ex.getRealException();
				} catch (IOException ex1) {
					throw new SshException(ex1.getMessage(),
							SshException.CHANNEL_FAILURE);
				}

				throw new SshException("The thread was interrupted",
						SshException.CHANNEL_FAILURE);
			} catch (IOException ex) {
				throw new SshException(SshException.INTERNAL_ERROR, ex);
			} finally {
				sync.releaseBlock();
			}
		}

		return (SftpMessage) responses.remove(requestId);

	}

	UnsignedInteger32 nextRequestId() {
		requestId = UnsignedInteger32.add(requestId, 1);
		return requestId;
	}

	class SftpThreadSynchronizer {

		boolean isBlocking = false;

		public boolean requestBlock(UnsignedInteger32 requestId,
				MessageHolder holder) throws InterruptedException {
			
			if (responses.containsKey(requestId)) {
				holder.msg = (Message) responses.get(requestId);
				return false;
			}
			
			synchronized(SftpThreadSynchronizer.this){
				
				boolean canBlock = !isBlocking;

				if (responses.containsKey(requestId)) {
					holder.msg = (Message) responses.get(requestId);
					return false;
				}
	
				if (canBlock) {
					isBlocking = true;
				} else {
					wait();
				}
	
				return canBlock;
			
			}

		}

		public synchronized void releaseBlock() {
			isBlocking = false;
			notifyAll();
		}

	}
}
