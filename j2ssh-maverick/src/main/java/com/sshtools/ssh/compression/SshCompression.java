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
package com.sshtools.ssh.compression;

import java.io.IOException;

/**
 * 
 * <p>
 * Compression interface which can be implemented to provide the SSH Transport
 * Protocol with compression.
 * </p>
 * 
 * @author Lee David Painter
 */
public interface SshCompression {

	/**
	 * Inflation mode
	 */
	static public final int INFLATER = 0;

	/**
	 * Deflation mode
	 */
	static public final int DEFLATER = 1;

	/**
	 * Initialize the compression.
	 * 
	 * @param type
	 *            the mode of the compression, should be either INFLATER or
	 *            DEFLATER
	 * @param level
	 *            the level of compression
	 */
	public void init(int type, int level);

	/**
	 * Compress a block of data.
	 * 
	 * @param data
	 *            the data to compress
	 * @param start
	 *            the offset of the data to compress
	 * @param len
	 *            the length of the data
	 * @return the compressed data with any uncompressed data at the start
	 *         remaining intact.
	 * @throws IOException
	 */
	public byte[] compress(byte[] data, int start, int len) throws IOException;

	/**
	 * Uncompress a block of data.
	 * 
	 * @param data
	 *            the data to uncompress
	 * @param start
	 *            the offset of the data to uncompress
	 * @param len
	 *            the length of the data
	 * @return the uncompressed data with any data not compressed at the start
	 *         remaining intact.
	 * @throws IOException
	 */
	public byte[] uncompress(byte[] data, int start, int len)
			throws IOException;

	/**
	 * Get the algorithm name for this compression implementation.
	 * 
	 * @return the algorithm name.
	 */
	public String getAlgorithm();

}
