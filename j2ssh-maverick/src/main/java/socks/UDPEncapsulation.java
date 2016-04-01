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
package socks;
/**
 This interface provides for datagram encapsulation for SOCKSv5 protocol.
 <p>
 SOCKSv5 allows for datagrams to be encapsulated for purposes of integrity
 and/or authenticity. How it should be done is aggreed during the 
 authentication stage, and is authentication dependent. This interface is
 provided to allow this encapsulation.
 @see Authentication
*/
public interface UDPEncapsulation{

    /**
    This method should provide any authentication depended transformation
    on datagrams being send from/to the client.

    @param data Datagram data (including any SOCKS related bytes), to be
                encapsulated/decapsulated.
    @param out  Wether the data is being send out. If true method should 
                encapsulate/encrypt data, otherwise it should decapsulate/
                decrypt data.
    @throw IOException if for some reason data can be transformed correctly.
    @return Should return byte array containing data after transformation.
            It is possible to return same array as input, if transformation
            only involves bit mangling, and no additional data is being
            added or removed.
    */
    byte[] udpEncapsulate(byte[] data, boolean out) throws java.io.IOException;
}
