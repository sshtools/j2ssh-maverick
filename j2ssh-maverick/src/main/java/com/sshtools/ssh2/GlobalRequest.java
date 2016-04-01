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

/**
 * 
 * <p>
 * This class represents a global request.
 * </p>
 * 
 * @author Lee David Painter
 */
public class GlobalRequest {

	String name;
	byte[] requestdata;

	/**
	 * Contstruct a request.
	 * 
	 * @param name
	 *            the name of the request
	 * @param requestdata
	 *            the request data
	 */
	public GlobalRequest(String name, byte[] requestdata) {
		this.name = name;
		this.requestdata = requestdata;
	}

	/**
	 * Get the name of the request.
	 * 
	 * @return String
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the request data, if the request has been sent and processed, this
	 * will return the response data (which can be null).
	 * 
	 * @return either the request data or response data according to the current
	 *         state.
	 */
	public byte[] getData() {
		return requestdata;
	}

	/**
	 * Set the data.
	 * 
	 * @param requestdata
	 */
	public void setData(byte[] requestdata) {
		this.requestdata = requestdata;
	}

}