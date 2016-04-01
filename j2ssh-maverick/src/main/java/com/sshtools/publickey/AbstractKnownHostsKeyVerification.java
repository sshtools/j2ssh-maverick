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
package com.sshtools.publickey;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.StringTokenizer;

import com.sshtools.ssh.HostKeyVerification;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.ComponentManager;
import com.sshtools.ssh.components.SshHmac;
import com.sshtools.ssh.components.SshPublicKey;
import com.sshtools.ssh.components.SshRsaPublicKey;
import com.sshtools.util.Base64;

/**
 * <p>
 * An abstract <a
 * href="../../maverick/ssh/HostKeyVerification.html">HostKeyVerification</a>
 * class implementation providing validation against the known_hosts format.
 * </p>
 * 
 * @author Lee David Painter
 */
public abstract class AbstractKnownHostsKeyVerification implements
		HostKeyVerification {

	private Hashtable<String,Hashtable<String,SshPublicKey>> allowedHosts = new Hashtable<String,Hashtable<String,SshPublicKey>>();
	private Hashtable<String,Hashtable<String,SshPublicKey>> temporaryHosts = new Hashtable<String,Hashtable<String,SshPublicKey>>();
	private String knownhosts;
	private boolean hostFileWriteable;
	private boolean hashHosts = true;
	private File knownhostsFile;

	// Hashed support
	private static final String HASH_MAGIC = "|1|";
	private static final String HASH_DELIM = "|";

	/**
	 * Construct a known_hosts database based on the default path of
	 * ~/.ssh/known_hosts.
	 * 
	 */
	public AbstractKnownHostsKeyVerification() throws SshException {
		this(null);
	}

	public File getKnownHostsFile() {
		return knownhostsFile;
	}

	/**
	 * <p>
	 * Constructs a known_hosts database based on the path provided.
	 * </p>
	 * 
	 * @param knownhosts
	 *            the path of the known_hosts file
	 * 
	 * @throws InvalidHostFileException
	 *             if the known_hosts file is invalid
	 * 
	 * @since 0.2.0
	 */
	public AbstractKnownHostsKeyVerification(String knownhosts)
			throws SshException {
		InputStream in = null;

		if (knownhosts == null) {
			String homeDir = "";
			try {
				homeDir = System.getProperty("user.home");
			} catch (SecurityException e) {
				// ignore
			}
			knownhostsFile = new File(homeDir, ".ssh" + File.separator
					+ "known_hosts");
			knownhosts = knownhostsFile.getAbsolutePath();
		} else {
			knownhostsFile = new File(knownhosts);
		}

		try {
			// If no host file is supplied, or there is not enough permission to
			// load
			// the file, then just create an empty list.
			if (System.getSecurityManager() != null) {
				System.getSecurityManager().checkRead(knownhosts);
			}

			// Load the hosts file. Do not worry if file doesn't exist, just
			// disable
			// save of
			if (knownhostsFile.exists()) {
				in = new FileInputStream(knownhostsFile);

				BufferedReader reader = new BufferedReader(
						new InputStreamReader(in));
				String line;

				while ((line = reader.readLine()) != null) {
					line = line.trim();
					if (!line.equals("")) {
						StringTokenizer tokens = new StringTokenizer(line, " ");

						if (!tokens.hasMoreTokens()) {
							// Do not fail just tell the implementation to allow
							// it to decide what to do.
							onInvalidHostEntry(line);
							continue;
						}

						String host = (String) tokens.nextElement();
						String algorithm = null;
						try {
							if (!tokens.hasMoreTokens()) {
								// Do not fail just tell the implementation to
								// allow it to decide what to do.
								onInvalidHostEntry(line);
								continue;
							}

							Integer.parseInt(algorithm = (String) tokens
									.nextElement());


							// Do not support SSH1 keys

						} catch (OutOfMemoryError ox) {
							reader.close();
							throw new SshException(
									"Error parsing known_hosts file, is your file corrupt? "
											+ knownhostsFile.getAbsolutePath(),
									SshException.POSSIBLE_CORRUPT_FILE);
						} catch (NumberFormatException ex) {
							if (!tokens.hasMoreTokens()) {
								// Do not fail just tell the implementation to
								// allow it to decide what to do.
								onInvalidHostEntry(line);
								continue;
							}
							String key = (String) tokens.nextElement();

							try {
								SshPublicKey pk;
								if (algorithm != null) {
									pk = SshPublicKeyFileFactory
											.decodeSSH2PublicKey(algorithm,
													Base64.decode(key));
								} else {
									pk = SshPublicKeyFileFactory
											.decodeSSH2PublicKey(Base64
													.decode(key));
								}

								putAllowedKey(host, pk, true);
							} catch (IOException ex2) {
								onInvalidHostEntry(line);
							} catch (OutOfMemoryError oex) {
								reader.close();
								throw new SshException(
										"Error parsing known_hosts file, is your file corrupt? "
												+ knownhostsFile
														.getAbsolutePath(),
										SshException.POSSIBLE_CORRUPT_FILE);
							}
						}
					}

				}

				reader.close();
				in.close();
				hostFileWriteable = knownhostsFile.canWrite();
			} else {
				// Try to create the file and its parents if necessary
				File parent = new File(knownhostsFile.getParent());
				parent.mkdirs();

				FileOutputStream out = new FileOutputStream(knownhostsFile);
				out.write(toString().getBytes());
				out.close();
				hostFileWriteable = true;
			}

			this.knownhosts = knownhosts;
		} catch (IOException ioe) {
			hostFileWriteable = false;
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException ioe) {
				}
			}
		}
	}

	public void setHashHosts(boolean hashHosts) {
		this.hashHosts = hashHosts;
	}

	protected void onInvalidHostEntry(String entry) throws SshException {
		// Do nothing
	}

	/**
	 * <p>
	 * Determines whether the host file is writable.
	 * </p>
	 * 
	 * @return true if the host file is writable, otherwise false
	 * 
	 * @since 0.2.0
	 */
	public boolean isHostFileWriteable() {
		return hostFileWriteable;
	}

	/**
	 * <p>
	 * Called by the <code>verifyHost</code> method when the host key supplied
	 * by the host does not match the current key recording in the known hosts
	 * file.
	 * </p>
	 * 
	 * @param host
	 *            the name of the host
	 * @param allowedHostKey
	 *            the current key recorded in the known_hosts file.
	 * @param actualHostKey
	 *            the actual key supplied by the user
	 * 
	 * @throws SshException
	 *             if an error occurs
	 * 
	 * @since 0.2.0
	 */
	public abstract void onHostKeyMismatch(String host,
			SshPublicKey allowedHostKey, SshPublicKey actualHostKey)
			throws SshException;

	/**
	 * <p>
	 * Called by the <code>verifyHost</code> method when the host key supplied
	 * is not recorded in the known_hosts file.
	 * </p>
	 * 
	 * <p>
	 * </p>
	 * 
	 * @param host
	 *            the name of the host
	 * @param key
	 *            the public key supplied by the host
	 * 
	 * @throws SshException
	 *             if an error occurs
	 * 
	 * @since 0.2.0
	 */
	public abstract void onUnknownHost(String host, SshPublicKey key)
			throws SshException;

	/**
	 * <p>
	 * Allows a host key, optionally recording the key to the known_hosts file.
	 * </p>
	 * 
	 * @param host
	 *            the name of the host
	 * @param pk
	 *            the public key to allow
	 * @param always
	 *            true if the key should be written to the known_hosts file
	 * 
	 * @throws InvalidHostFileException
	 *             if the host file cannot be written
	 * 
	 * @since 0.2.0
	 */
	public void allowHost(String host, SshPublicKey pk, boolean always)
			throws SshException {

		// Put the host into the allowed hosts list, overiding any previous
		// entry
		if (hashHosts) {
			SshHmac sha1 = (SshHmac) ComponentManager.getInstance()
					.supportedHMacsCS().getInstance("hmac-sha1");
			byte[] hashSalt = new byte[sha1.getMacLength()];
			ComponentManager.getInstance().getRND().nextBytes(hashSalt);

			sha1.init(hashSalt);
			sha1.update(host.getBytes());

			byte[] theHash = sha1.doFinal();

			String names = HASH_MAGIC + Base64.encodeBytes(hashSalt, false)
					+ HASH_DELIM + Base64.encodeBytes(theHash, false);

			putAllowedKey(names, pk, always);
		} else {
			putAllowedKey(host, pk, always);
		}

		// allowedHosts.put(host, pk);
		// If we always want to allow then save the host file with the
		// new details
		if (always) {
			try {
				saveHostFile();
			} catch (IOException ex) {
				throw new SshException("knownhosts file could not be saved! "
						+ ex.getMessage(), SshException.INTERNAL_ERROR);
			}
		}
	}

	/**
	 * <p>
	 * Returns a Map of the allowed hosts.
	 * </p>
	 * 
	 * <p>
	 * The keys of the returned Map are comma separated strings of
	 * "hostname,ipaddress". The value objects are Maps containing a string key
	 * of the public key alogorithm name and the public key as the value.
	 * </p>
	 * 
	 * @return Hashtable<String,Hashtable<String,SshPublicKey>>
	 * 
	 * @since 0.2.0
	 */
	public Hashtable<String,Hashtable<String,SshPublicKey>> allowedHosts() {
		return allowedHosts;
	}

	/**
	 * <p>
	 * Removes an allowed host.
	 * </p>
	 * 
	 * @param host
	 *            the host to remove
	 * 
	 * @since 0.2.0
	 */
	public synchronized void removeAllowedHost(String host) {

		if (allowedHosts.containsKey(host)) {
			allowedHosts.remove(host);
		}
		/*
		 * for (Enumeration e = allowedHosts.keys(); e.hasMoreElements(); ) {
		 * StringTokenizer tokens = new StringTokenizer( (String)
		 * e.nextElement(), ",");
		 * 
		 * while (tokens.hasMoreElements()) { String name = (String)
		 * tokens.nextElement();
		 * 
		 * if (name.equals(host)) { allowedHosts.remove(name); } } }
		 */
	}

	/**
	 * <p>
	 * Verifies a host key against the list of known_hosts.
	 * </p>
	 * 
	 * <p>
	 * If the host unknown or the key does not match the currently allowed host
	 * key the abstract <code>onUnknownHost</code> or
	 * <code>onHostKeyMismatch</code> methods are called so that the caller may
	 * identify and allow the host.
	 * </p>
	 * 
	 * @param host
	 *            the name of the host
	 * @param pk
	 *            the host key supplied
	 * 
	 * @return true if the host is accepted, otherwise false
	 * 
	 * @throws SshException
	 *             if an error occurs
	 * 
	 * @since 0.2.0
	 */
	public boolean verifyHost(String host, SshPublicKey pk) throws SshException {
		return verifyHost(host, pk, true);
	}

	private synchronized boolean verifyHost(String host, SshPublicKey pk,
			boolean validateUnknown) throws SshException {

		String fqn = null;
		String ip = null;

		if (System.getProperty("maverick.knownHosts.enableReverseDNS", "true")
				.equalsIgnoreCase("true")) {
			try {
				InetAddress addr = InetAddress.getByName(host);

				fqn = addr.getHostName();
				ip = addr.getHostAddress();

			} catch (UnknownHostException ex) {
				// Just record the host as the user typed it
			}
		}

		for (Enumeration<String> e = allowedHosts.keys(); e.hasMoreElements();) {
			// Could be a comma delimited string of names/ip addresses
			String names = (String) e.nextElement();

			if (names.startsWith(HASH_MAGIC)) {
				// Create hash
				if (checkHash(names, host)) {
					return validateHost(names, pk);
				}

				if (ip != null) {
					if (checkHash(names, ip)) {
						return validateHost(names, pk);
					}
				}
			} else if (names.equals(host)) {
				return validateHost(names, pk);
			}

			StringTokenizer tokens = new StringTokenizer(names, ",");

			while (tokens.hasMoreElements()) {
				// Try the allowed hosts by looking at the allowed hosts map
				String name = (String) tokens.nextElement();

				if ((fqn != null && name.equals(fqn))
						|| (ip != null && name.equals(ip))) {
					return validateHost(names, pk);
				}
			}
		}

		for (Enumeration<String> e = temporaryHosts.keys(); e.hasMoreElements();) {
			// Could be a comma delimited string of names/ip addresses
			String names = e.nextElement();

			if (names.startsWith(HASH_MAGIC)) {
				// Create hash
				if (checkHash(names, host)) {
					return validateHost(names, pk);
				}

				if (ip != null) {
					if (checkHash(names, ip)) {
						return validateHost(names, pk);
					}
				}
			} else if (names.equals(host)) {
				return validateHost(names, pk);
			}

			StringTokenizer tokens = new StringTokenizer(names, ",");

			while (tokens.hasMoreElements()) {
				// Try the allowed hosts by looking at the allowed hosts map
				String name = (String) tokens.nextElement();

				if ((fqn != null && name.equals(fqn))
						|| (ip != null && name.equals(ip))) {
					return validateHost(names, pk);
				}
			}
		}
		// The host is unknown os ask the user
		if(!validateUnknown)
			return false;
		
		onUnknownHost(host, pk);

		// Recheck ans return the result
		return verifyHost(host, pk, false);
	}

	private boolean checkHash(String names, String host) throws SshException {
		SshHmac sha1 = (SshHmac) ComponentManager.getInstance()
				.supportedHMacsCS().getInstance("hmac-sha1");
		String hashData = names.substring(HASH_MAGIC.length());
		String hashSalt = hashData.substring(0, hashData.indexOf(HASH_DELIM));
		String hashStr = hashData.substring(hashData.indexOf(HASH_DELIM) + 1);

		byte[] theHash = Base64.decode(hashStr);

		sha1.init(Base64.decode(hashSalt));
		sha1.update(host.getBytes());

		byte[] ourHash = sha1.doFinal();

		return Arrays.equals(theHash, ourHash);
	}

	private boolean validateHost(String names, SshPublicKey pk)
			throws SshException {
		// The host is allowed so check the fingerprint
		SshPublicKey pub = getAllowedKey(names, pk.getAlgorithm());

		if ((pub != null) && pk.equals(pub)) {
			return true;
		}
		// The host key does not match the recorded so call the abstract
		// method so that the user can decide
		if (pub == null) {
			onUnknownHost(names, pk);
		} else {
			onHostKeyMismatch(names, pub, pk);
		}

		// Recheck the after the users input
		return checkKey(names, pk);
	}

	private boolean checkKey(String host, SshPublicKey key) {
		SshPublicKey pk = getAllowedKey(host, key.getAlgorithm());

		if (pk != null) {
			if (pk.equals(key)) {
				return true;
			}
		}

		return false;
	}

	private synchronized SshPublicKey getAllowedKey(String names, String algorithm) {

		try {
			for (Iterator<String> it = temporaryHosts.keySet().iterator(); it.hasNext();) {
				String name = it.next();
				if (name.startsWith(HASH_DELIM)) {
					if (checkHash(name, names)) {
						Hashtable<String,SshPublicKey> map = temporaryHosts.get(name);
						return (SshPublicKey) map.get(algorithm);
					}
				}
			}
		} catch (SshException e) {

		}

		if (temporaryHosts.containsKey(names)) {
			Hashtable<String,SshPublicKey> map = temporaryHosts.get(names);
			return (SshPublicKey) map.get(algorithm);
		}

		try {
			for (Iterator<String> it = allowedHosts.keySet().iterator(); it.hasNext();) {
				String name = (String) it.next();
				if (name.startsWith(HASH_DELIM)) {
					if (checkHash(name, names)) {
						Hashtable<String,SshPublicKey> map = allowedHosts.get(name);
						return (SshPublicKey) map.get(algorithm);
					}
				}
			}
		} catch (SshException e) {

		}
		if (allowedHosts.containsKey(names)) {
			Hashtable<String,SshPublicKey> map = allowedHosts.get(names);
			return (SshPublicKey) map.get(algorithm);
		}
		return null;
	}

	private synchronized void putAllowedKey(String host, SshPublicKey key, boolean always) {

		if (always) {
			if (!allowedHosts.containsKey(host)) {
				allowedHosts.put(host, new Hashtable<String,SshPublicKey>());
			}

			Hashtable<String,SshPublicKey> keys = allowedHosts.get(host);
			keys.put(key.getAlgorithm(), key);
		} else {
			if (!temporaryHosts.containsKey(host)) {
				temporaryHosts.put(host, new Hashtable<String,SshPublicKey>());
			}

			Hashtable<String,SshPublicKey> keys = temporaryHosts.get(host);
			keys.put(key.getAlgorithm(), key);
		}
	}

	/**
	 * <p>
	 * Save's the host key file to be saved.
	 * </p>
	 * 
	 * @throws InvalidHostFileException
	 *             if the host file is invalid
	 * 
	 * @since 0.2.0
	 */
	public synchronized void saveHostFile() throws IOException {
		if (!hostFileWriteable) {
			throw new IOException("Host file is not writeable.");
		}

		try {
			File f = new File(knownhosts);

			FileOutputStream out = new FileOutputStream(f);

			out.write(toString().getBytes());

			out.close();
		} catch (IOException e) {
			throw new IOException("Could not write to " + knownhosts);
		}
	}

	/**
	 * <p>
	 * Outputs the allowed hosts in the known_hosts file format.
	 * </p>
	 * 
	 * <p>
	 * The format consists of any number of lines each representing one key for
	 * a single host.
	 * </p>
	 * <code> titan,192.168.1.12 ssh-dss AAAAB3NzaC1kc3MAAACBAP1/U4Ed.....
	 * titan,192.168.1.12 ssh-rsa AAAAB3NzaC1kc3MAAACBAP1/U4Ed.....
	 * einstein,192.168.1.40 ssh-dss AAAAB3NzaC1kc3MAAACBAP1/U4Ed..... </code>
	 * 
	 * @return String
	 * 
	 * @since 0.2.0
	 */
	public String toString() {

		StringBuffer knownhostsBuf = new StringBuffer("");
		String eol = System.getProperty("line.separator");

		for (Enumeration<String> e = allowedHosts.keys(); e.hasMoreElements();) {

			String host = e.nextElement();
			Hashtable<String,SshPublicKey> table = allowedHosts.get(host);

			for (Enumeration<String> e2 = table.keys(); e2.hasMoreElements();) {

				String type = e2.nextElement();

				SshPublicKey pk = (SshPublicKey) table.get(type);
				if (pk instanceof SshRsaPublicKey
						&& ((SshRsaPublicKey) pk).getVersion() == 1) {

					SshRsaPublicKey ssh1 = (SshRsaPublicKey) pk;
					knownhostsBuf.append(host + " "
							+ String.valueOf(ssh1.getModulus().bitLength())
							+ " " + ssh1.getPublicExponent() + " "
							+ ssh1.getModulus() + eol);
				} else {
					try {
						knownhostsBuf
								.append((host
										+ " "
										+ pk.getAlgorithm()
										+ " "
										+ Base64.encodeBytes(pk.getEncoded(),
												true) + eol));
					} catch (SshException ex) {
						// Bad encoding... Ignore??
					}
				}

			}
		}

		return knownhostsBuf.toString();
	}
}
