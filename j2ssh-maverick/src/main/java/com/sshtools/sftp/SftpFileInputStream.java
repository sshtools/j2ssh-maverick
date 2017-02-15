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
package com.sshtools.sftp;

import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshIOException;
import com.sshtools.util.UnsignedInteger32;

/**
 * <p>
 * An InputStream to read the contents of a remote file.
 * </p>
 * <blockquote>
 * 
 * <pre>
 * // Create an SshClient forcing SSH2 connectivity.
 * SshConnector con = SshConnector.getInstance();
 * con.setSupportedVersions(SshConnector.SSH2);
 * 
 * // Connect and authenticate an SshClient
 * Ssh2Client ssh = (Ssh2Client) con.connect(....);
 * ....
 * 
 * SftpClient sftp=new SftpClient(ssh);
 * 
 * //read file as input stream
 * 	InputStream in = sftp.getInputStream("streamTest");
 * 	
 * 	 // Read the data
 * 	 int read;
 * 	 while((read = in.read()) > -1){
 * 		//do something with data
 * 	 }
 * 
 * 	 // Close the file and the stream
 * 	 in.close();
 * 
 * @author Lee David Painter
 */
public class SftpFileInputStream extends InputStream {

	SftpFile file;
	SftpSubsystemChannel sftp;
	long position;
	Vector<UnsignedInteger32> outstandingRequests = new Vector<UnsignedInteger32>();
	SftpMessage currentMessage;
	int currentMessageRemaining;
	boolean isEOF = false;

	/**
	 * 
	 * @param file
	 * @throws SftpStatusException
	 * @throws SshException
	 */
	public SftpFileInputStream(SftpFile file) throws SftpStatusException,
			SshException {
		this(file, 0);
	}

	/**
	 * Creates a new SftpFileInputStream object.
	 * 
	 * @param file
	 * @param position
	 *            at which to start reading
	 * @throws SftpStatusException
	 * @throws SshException
	 */
	public SftpFileInputStream(SftpFile file, long position)
			throws SftpStatusException, SshException {
		if (file.getHandle() == null) {
			throw new SftpStatusException(SftpStatusException.INVALID_HANDLE,
					"The file does not have a valid handle!");
		}

		if (file.getSFTPChannel() == null) {
			throw new SshException(
					"The file is not attached to an SFTP subsystem!",
					SshException.BAD_API_USAGE);
		}

		this.file = file;
		this.position = position;
		this.sftp = file.getSFTPChannel();

		try {
			bufferNextMessage();
		} catch (IOException e) {
			throw new SshException(e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.InputStream#read(byte[], int, int)
	 */
	public int read(byte[] buffer, int offset, int len) throws IOException {

		try {

			if (isEOF && currentMessageRemaining == 0) {
				return -1;
			}

			int read = 0;
			int wantsLength = len;
			while (read < wantsLength && !isEOF) {

				if (currentMessage == null || currentMessageRemaining == 0) {
					bufferNextMessage();
					if (isEOF && read == 0) {
						return -1;
					}
				}

				if (currentMessage == null)
					throw new IOException(
							"Failed to obtain file data or status from the SFTP server!");

				int count = Math.min(currentMessageRemaining, len);

				System.arraycopy(currentMessage.array(),
						currentMessage.getPosition(), buffer, offset, count);

				currentMessageRemaining -= count;
				currentMessage.skip(count);

				if (currentMessageRemaining == 0) {
					bufferNextMessage();
				}
				read += count;
				len -= count;
				offset += count;

			}

			return read;
		} catch (SshException ex) {
			throw new SshIOException(ex);
		} catch (SftpStatusException ex) {
			throw new IOException(ex.getMessage());
		}
	}

	private void bufferNextMessage() throws SshException, IOException,
			SftpStatusException {

		bufferMoreData();

		UnsignedInteger32 requestid = (UnsignedInteger32) outstandingRequests
				.elementAt(0);
		currentMessage = sftp.getResponse(requestid);
		outstandingRequests.removeElementAt(0);

		if (currentMessage.getType() == SftpSubsystemChannel.SSH_FXP_DATA) {
			currentMessageRemaining = (int) currentMessage.readInt();
		} else if (currentMessage.getType() == SftpSubsystemChannel.SSH_FXP_STATUS) {
			int status = (int) currentMessage.readInt();
			if (status == SftpStatusException.SSH_FX_EOF) {
				isEOF = true;
				return;
			}
			if (sftp.getVersion() >= 3) {
				String desc = currentMessage.readString().trim();
				throw new IOException(desc);
			}
			throw new IOException("Unexpected status " + status);
		} else {
			close();
			throw new IOException(
					"The server responded with an unexpected SFTP protocol message! type="
							+ currentMessage.getType());
		}
	}

	private void bufferMoreData() throws SftpStatusException, SshException {
		while (outstandingRequests.size() < 100) {
			outstandingRequests.addElement(sftp.postReadRequest(
					file.getHandle(), position, 32768));
			position += 32768;
		}
	}

	public int available() {
		return currentMessageRemaining;
	}

	/**
   *
   */
	public int read() throws java.io.IOException {
		byte[] b = new byte[1];
		if (read(b) == 1) {
			int val = (b[0] & 0xFF);
			return val;
		}
		return -1;
	}

	/**
	 * Closes the SFTP file handle.
	 */
	public void close() throws IOException {
		try {
			file.close();

			UnsignedInteger32 requestid;
			while (outstandingRequests.size() > 0) {
				requestid = (UnsignedInteger32) outstandingRequests
						.elementAt(0);
				outstandingRequests.removeElementAt(0);
				sftp.getResponse(requestid);
			}
		} catch (SshException ex) {
			throw new SshIOException(ex);
		} catch (SftpStatusException ex) {
			throw new IOException(ex.getMessage());
		}
	}

	/**
	 * This method will only be available in J2SE builds
	 */
	// J2SE protected void finalize() throws IOException {
	// J2SE if (file.getHandle() != null) {
	// J2SE close();
	// J2SE }
	// J2SE }

}
