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
/**
 * This file is originally from the http://sourceforge.net/projects/jsocks/
 * released under the LGPL.
 */
package socks;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
  Proxy which describes SOCKS4 proxy.
*/

public class Socks4Proxy extends Proxy implements Cloneable{

//Data members
   String user;

//Public Constructors
//====================

   /**
     Creates the SOCKS4 proxy
     @param p Proxy to use to connect to this proxy, allows proxy chaining.
     @param proxyHost Address of the proxy server.
     @param proxyPort Port of the proxy server
     @param user User name to use for identification purposes.
     @throws UnknownHostException If proxyHost can't be resolved.
    */
   public Socks4Proxy(Proxy p,String proxyHost,int proxyPort,String user)
          throws UnknownHostException{ 
      super(p,proxyHost,proxyPort);
      this.user = new String(user);
      version = 4;
   }

   /**
     Creates the SOCKS4 proxy
     @param proxyHost Address of the proxy server.
     @param proxyPort Port of the proxy server
     @param user User name to use for identification purposes.
     @throws UnknownHostException If proxyHost can't be resolved.
    */
   public Socks4Proxy(String proxyHost,int proxyPort,String user)
          throws UnknownHostException{ 
      this(null,proxyHost,proxyPort,user);
   }

   /**
     Creates the SOCKS4 proxy
     @param p Proxy to use to connect to this proxy, allows proxy chaining.
     @param proxyIP Address of the proxy server.
     @param proxyPort Port of the proxy server
     @param user User name to use for identification purposes.
    */
   public Socks4Proxy(Proxy p,InetAddress proxyIP,int proxyPort,String user){
      super(p,proxyIP,proxyPort);
      this.user = new String(user);
      version = 4;
   }

   /**
     Creates the SOCKS4 proxy
     @param proxyIP Address of the proxy server.
     @param proxyPort Port of the proxy server
     @param user User name to use for identification purposes.
    */
   public Socks4Proxy(InetAddress proxyIP,int proxyPort,String user){
      this(null,proxyIP,proxyPort,user);
   }

//Public instance methods
//========================

   /**
    * Creates a clone of this proxy. Changes made to the clone should not
    * affect this object. 
    */
   public Object clone(){
      Socks4Proxy newProxy = new Socks4Proxy(proxyIP,proxyPort,user);
      newProxy.directHosts = (InetRange)directHosts.clone();
      newProxy.chainProxy = chainProxy;
      return newProxy;
   }


//Public Static(Class) Methods
//==============================


//Protected Methods
//=================

   protected Proxy copy(){
       Socks4Proxy copy = new Socks4Proxy(proxyIP,proxyPort,user);
       copy.directHosts = this.directHosts;
       copy.chainProxy = chainProxy;
       return copy;
    }

   protected ProxyMessage formMessage(int cmd,InetAddress ip,int port){
       switch(cmd){
         case SOCKS_CMD_CONNECT:
           cmd = Socks4Message.REQUEST_CONNECT;
         break;
         case SOCKS_CMD_BIND:
           cmd = Socks4Message.REQUEST_BIND;
         break;
         default:
           return null;
       }
       return new Socks4Message(cmd,ip,port,user);
   }
   protected ProxyMessage formMessage(int cmd,String host,int port)
             throws UnknownHostException{
       return formMessage(cmd,InetAddress.getByName(host),port);
   }
   protected ProxyMessage formMessage(InputStream in)
             throws SocksException,
                    IOException{
       return new Socks4Message(in,true);
   }

}
