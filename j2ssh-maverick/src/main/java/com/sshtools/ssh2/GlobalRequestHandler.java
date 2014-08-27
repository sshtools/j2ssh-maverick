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

import com.sshtools.ssh.SshException;

/**
 * <p>There are several kinds of requests that affect the state of the remote end "globally",
 * independent of any channels, this interface defines the contract for handling such global
 * requests.
 * </p>
 *
 * @author Lee David Painter
 */
public interface GlobalRequestHandler {

  /**
   * Return the supported request types.
   * @return an array of Strings containing the supported request types.
   */
  public String[] supportedRequests();

  /**
   * Called when a supported global request has been recieved.
   * @param request
   * @return <code>true</code> if the request succeeded, otherwise <code>false</code>
   * @throws IOException
   */
  public boolean processGlobalRequest(GlobalRequest request) throws SshException;
}
