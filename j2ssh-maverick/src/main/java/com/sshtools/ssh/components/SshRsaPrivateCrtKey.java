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
package com.sshtools.ssh.components;

import java.math.BigInteger;

import com.sshtools.ssh.SshException;

/**
 * This interface should be implemented by all RSA private co-efficient private
 * key implementations.
 * 
 * @author Lee David Painter
 */
public interface SshRsaPrivateCrtKey extends SshRsaPrivateKey {

	public BigInteger getPublicExponent();

	public BigInteger getPrimeP();

	public BigInteger getPrimeQ();

	public BigInteger getPrimeExponentP();

	public BigInteger getPrimeExponentQ();

	public BigInteger getCrtCoefficient();

	BigInteger doPrivate(BigInteger input) throws SshException;
}