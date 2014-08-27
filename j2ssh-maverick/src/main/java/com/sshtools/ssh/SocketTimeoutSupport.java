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
package com.sshtools.ssh;

import java.io.IOException;

/**
 * <p>This interface adds timeout support to the {@see SocketTransport} interface.</p>
 *
 * @author Lee David Painter
 */
public interface SocketTimeoutSupport {

        /**
         * Set the socket timeout in milliseconds.
         * @param timeout int
         * @throws IOException
         */
        public void setSoTimeout(int timeout) throws IOException;

        /**
         * Get the current socket timeout in milliseconds.
         * @return int
         * @throws IOException
         */
        public int getSoTimeout() throws IOException;
}
