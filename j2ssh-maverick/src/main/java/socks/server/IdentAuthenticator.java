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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import socks.InetRange;
import socks.ProxyMessage;

/**
  An implementation of socks.ServerAuthentication which provides
  simple authentication based on the host from which the connection
  is made and the name of the user on the remote machine, as reported
  by identd daemon on the remote machine.
  <p>
  It can also be used to provide authentication based only on the contacting
  host address.
*/

public class IdentAuthenticator extends ServerAuthenticatorNone{
   /** Vector of InetRanges */
   Vector<InetRange> hosts;

   /** Vector of user hashes*/
   Vector<Hashtable<String,Object>> users;

   String user;


   /**
    Constructs empty IdentAuthenticator.
   */
   public IdentAuthenticator(){
      hosts = new Vector<InetRange>();
      users = new Vector<Hashtable<String,Object>>();
   }
   /**
    Used to create instances returned from startSession.
    @param in Input stream.
    @param out OutputStream.
    @param user Username associated with this connection,could be
                null if name was not required.
   */
   IdentAuthenticator(InputStream in,OutputStream out, String user){
      super(in,out);
      this.user = user;
   }

   /**
    Adds range of addresses from which connection is allowed. Hashtable
    users should contain user names as keys and anything as values
    (value is not used and will be ignored). 
    @param hostRange Range of ip addresses from which connection is allowed.
    @param users Hashtable of users for whom connection is allowed, or null
    to indicate that anybody is allowed to connect from the hosts within given
    range.
   */
   public synchronized void add(InetRange hostRange,Hashtable<String,Object> users){
      this.hosts.addElement(hostRange);
      this.users.addElement(users);
   }

   /**
     Grants permission only to those users, who connect from one of the
     hosts registered with add(InetRange,Hashtable) and whose names, as
     reported by identd daemon, are listed for the host the connection
     came from.
    */
   public ServerAuthenticator startSession(Socket s)
                              throws IOException{

     int ind = getRangeIndex(s.getInetAddress());
     String user = null;

     //System.out.println("getRangeReturned:"+ind);

     if(ind < 0) return null; //Host is not on the list.

     ServerAuthenticatorNone auth = (ServerAuthenticatorNone)
                                    super.startSession(s);

     //System.out.println("super.startSession() returned:"+auth);
     if(auth == null) return null;

     //do the authentication 

     Hashtable<String,Object> user_names = users.elementAt(ind); 

     if(user_names != null){ //If need to do authentication
       Ident ident;
       ident = new Ident(s);
       //If can't obtain user name, fail
       if(!ident.successful) return null;
       //If user name is not listed for this address, fail
       if(!user_names.containsKey(ident.userName)) return null;
       user = ident.userName;
     }
     return new IdentAuthenticator(auth.in,auth.out,user);

   }
   /**
    For SOCKS5 requests allways returns true. For SOCKS4 requests
    checks wether the user name supplied in the request corresponds
    to the name obtained from the ident daemon.
   */
   public boolean checkRequest(ProxyMessage msg,java.net.Socket s){
     //If it's version 5 request, or if anybody is permitted, return true;
     if(msg.version == 5 || user == null) 
       return true;

     if(msg.version != 4) return false; //Who knows?

     return user.equals(msg.user);
   }

  /** Get String representaion of the IdentAuthenticator.*/
  public String toString(){
     String s = "";

     for(int i=0;i<hosts.size();++i)
        s += "Range:"+hosts.elementAt(i)+"\nUsers:"+userNames(i)+"\n";
     return s;
  }

//Private Methods
//////////////////
  private int getRangeIndex(InetAddress ip){
     int index = 0;
     Enumeration<InetRange> e = hosts.elements();
     while(e.hasMoreElements()){
       InetRange ir = (InetRange) e.nextElement();
       if(ir.contains(ip)) return index;
       index++;
     }
     return -1; //Not found
  }

  private String userNames(int i){
    if(users.elementAt(i) == null) return "Everybody is permitted.";

    Enumeration<String> e = users.elementAt(i).keys();
    if(!e.hasMoreElements()) return "";
    String s = e.nextElement().toString();
    while(e.hasMoreElements())
       s += "; "+e.nextElement();

    return s;
  }

}
