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
package com.sshtools.ssh.components.jce;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;

import com.sshtools.ssh.components.SshPrivateKey;
import com.sshtools.util.ByteArrayWriter;
import com.sshtools.util.SimpleASNReader;

public class Ssh2EcdsaSha2NistPrivateKey implements SshPrivateKey {

	String name;
	String spec;
	String curve;
	
	ECPrivateKey prv;
	
	public Ssh2EcdsaSha2NistPrivateKey(ECPrivateKey prv) throws IOException {
        this.prv = prv;
        String curve = prv.getParams().toString();
    	if(curve.contains("prime256v1") || curve.contains("secp256r1")) {
    		this.curve = "secp256r1";
    		this.name = "ecdsa-sha2-nistp256";
    		this.spec = "SHA256/ECDSA";
    	} else if(curve.contains("secp384r1")) {
    		this.curve = "secp384r1";
    		this.name = "ecdsa-sha2-nistp384";
    		this.spec = "SHA384/ECDSA";        		
    	} else if(curve.contains("secp521r1")) {
    		this.curve = "secp521r1";
    		this.name = "ecdsa-sha2-nistp521";
    		this.spec = "SHA512/ECDSA";
    	} else {
    		throw new IOException("Unsupported curve name " + curve);
    	}
	}
	
	public byte[] sign(byte[] data) throws IOException {
		try {
			Signature sig = JCEProvider.getProviderForAlgorithm(spec) == null ? Signature.getInstance(spec) : Signature.getInstance(spec, JCEProvider.getProviderForAlgorithm(spec));
            sig.initSign(prv);
            sig.update(data);
            byte[] sigRaw = sig.sign();
            ByteArrayWriter baw = new ByteArrayWriter();
            try {
                SimpleASNReader asn = new SimpleASNReader(sigRaw);
                
                asn.getByte();
                asn.getLength();
                asn.getByte();

                byte[] r = asn.getData();
                asn.getByte();

                byte[] s = asn.getData();

                baw.writeBinaryString(r);
                baw.writeBinaryString(s);
                return baw.toByteArray();
            } catch (IOException ioe) {
                throw new IOException("DER decode failed: " + ioe.getMessage());
            } finally {
            	baw.close();
            }
        } catch (Exception e) {
            throw new IOException("Error in " + name +
                                             " sign: " + e.getMessage());
        }

	}

	public String getAlgorithm() {
		return name;
	}

	public PrivateKey getJCEPrivateKey() {
		return prv;
	}

}
