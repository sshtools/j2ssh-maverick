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
/**
 * This file is originally from the http://sourceforge.net/projects/jsocks/
 * released under the LGPL.
 */
package socks.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
  This class implements SOCKS5 User/Password authentication scheme as
  defined in rfc1929,the server side of it.
*/
public class UserPasswordAuthenticator extends  ServerAuthenticatorNone{

   static final int METHOD_ID = 2;

   UserValidation validator;

   /**
    Construct a new UserPasswordAuthentication object, with given
    UserVlaidation scheme.

    @param v UserValidation to use for validating users.
   */
   public UserPasswordAuthenticator(UserValidation validator){
      this.validator = validator;
   }

   public ServerAuthenticator startSession(Socket s) throws IOException{
     InputStream in = s.getInputStream();
     OutputStream out = s.getOutputStream();

     if(in.read() != 5) return null; //Drop non version 5 messages.

     if(!selectSocks5Authentication(in,out,METHOD_ID)) 
       return null;
     if(!doUserPasswordAuthentication(s,in,out))
       return null;

     return new ServerAuthenticatorNone(in,out);
   }


//Private Methods
//////////////////

   private boolean doUserPasswordAuthentication(Socket s,
                                                InputStream in,
                                                OutputStream out) 
                                                throws IOException{
     int version = in.read();
     if(version != 1) return false;
     int ulen = in.read();
     if(ulen < 0) return false;
     byte[] user = new byte[ulen];
     in.read(user);
     int plen = in.read();
     if(plen < 0) return false;
     byte[] password = new byte[plen];
     in.read(password);

     if(validator.isUserValid(new String(user), new String(password),s)){
       //System.out.println("user valid");
       out.write(new byte[]{1,0});
     }else{
       //System.out.println("user invalid");
       out.write(new byte[]{1,1});
       return false;
     }

     return true;
   }
}
