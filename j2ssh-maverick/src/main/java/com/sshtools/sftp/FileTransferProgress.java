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

/**
 * <p>
 * Interface for monitoring the state of a file transfer
 * </p>
 * 
 * <p>
 * It should be noted that the total bytes to transfer passed to the started
 * method is an indication of file length and may not be exact for some types of
 * file transfer, for example ASCII text mode transfers may add or remove
 * newline characters from the stream and therefore the total bytes transfered
 * may not equal the number expected.
 * 
 * @author Lee David Painter
 */
public interface FileTransferProgress {
	/**
	 * The transfer has started
	 * 
	 * @param bytesTotal
	 * @param remoteFile
	 */
	public void started(long bytesTotal, String remoteFile);

	/**
	 * The transfer is cancelled. Implementations should return true if the user
	 * wants to cancel the transfer. The transfer will then be stopped at the
	 * next evaluation stage.
	 * 
	 * @return boolean
	 */
	public boolean isCancelled();

	/**
	 * The transfer has progressed
	 * 
	 * @param bytesSoFar
	 */
	public void progressed(long bytesSoFar);

	/**
	 * The transfer has completed.
	 */
	public void completed();
}
