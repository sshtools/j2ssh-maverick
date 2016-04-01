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
/**
 * This file is originally from the http://sourceforge.net/projects/jsocks/
 * released under the LGPL.
 */
package socks.server;

/**
  Interface which provides for user validation, based on user name
  password and where it connects from.
*/
public interface UserValidation{
    /**
     Implementations of this interface are expected to use some or all
     of the information provided plus any information they can extract
     from other sources to decide wether given user should be allowed
     access to SOCKS server, or whatever you use it for.

     @return true to indicate user is valid, false otherwise.
     @param username User whom implementation should validate.
     @param password Password this user provided.
     @param connection Socket which user used to connect to the server.
    */
    boolean isUserValid(String username,String password,
                        java.net.Socket connection);
}
