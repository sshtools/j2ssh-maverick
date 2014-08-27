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

package com.sshtools.ssh.components;

import java.util.Hashtable;
import java.util.Vector;

import com.sshtools.ssh.SshException;
import com.sshtools.util.Arrays;

/**
 * <p>A utility class used to store the available transport components
 * and provide delimited listing as required in the key exchange initialization
 * process.</p>
 *
 * @author Lee David Painter
 */
public class ComponentFactory implements Cloneable {

  /**
   * The supported components stored in a Hashtable with a String
   * key as the component name such as "3des-cbc" and a Class value
   * storing the implementation class.
   */
  protected Hashtable<String, Class<?>> supported = new Hashtable<String, Class<?>>();
  protected Vector<Object> order=new Vector<Object>();
  Class<?> type;
  
  private boolean locked;

  public synchronized String changePositionofAlgorithm(String name, int position) throws SshException {
	  
	  
	  if(position<0) {
		  throw new SshException("index out of bounds",SshException.BAD_API_USAGE);
	  }
	  
	  if(position>=order.size()) {
		  position=order.size();
	  }
	  
	  int currentLocation=order.indexOf(name);
	  if(currentLocation<position) {
		  order.insertElementAt(name, position);
		  order.removeElementAt(currentLocation);
	  }
	  else {
		  order.removeElementAt(currentLocation);
		  order.insertElementAt(name, position);
	  }

	  return (String) order.elementAt(0);
  }
  
  
  public synchronized String createNewOrdering(int[] ordering) throws SshException {
	  if(ordering.length>order.size()) {
		  throw new SshException("too many indicies",SshException.BAD_API_USAGE);
	  }
	  
	  //move indices specified in ordering to end of vector
	  for(int i=0;i<ordering.length;i++) {
		  if(!(ordering[i]>=0 && ordering[i]<order.size())) {
			  throw new SshException("index out of bounds",SshException.BAD_API_USAGE);
		  }
		  order.insertElementAt(order.elementAt(ordering[i]), order.size());
	  }
	  //sort ordering indices so that remove lowest indices first
	  Arrays.sort(ordering);
	  //remove from order starting from end
	  for(int i=(ordering.length-1);i>=0;i--) {
		  order.removeElementAt(ordering[i]);
	  }
	  //move ones moved to end to beginning starting from end
	  for(int i=0;i<ordering.length;i++) {
		  Object element=order.elementAt(order.size()-1);
		  order.removeElementAt(order.size()-1);
		  order.insertElementAt(element, 0);
	  }
	  
	  return (String) order.elementAt(0);
  }
  
  /**
   * Create a component factory with the base class supplied.
   * @param type
   * @throws java.lang.ClassNotFoundException Thrown if the class cannot
   *                                          be resolved.
   */
  public ComponentFactory(Class<?> type) {
    this.type = type;
  }

  /**
   * Determine whether the factory supports a given component type.
   * @param name
   * @return <code>true</code> if the component is supported otherwise
   *         <code>false</code>
   */
  public boolean contains(String name) {
    return supported.containsKey(name);
  }

  /**
   * List the types of components supported by this factory. Returns the
   * list as a comma delimited string with the preferred value as the first
   * entry in the list. If the preferred value is "" then the list is returned
   * unordered.
   * @param preferred The preferred component type.
   * @return A comma delimited String of component types; for example "3des-cbc,blowfish-cbc"
   */
  public synchronized String list(String preferred) {
    return createDelimitedList(preferred);
  }
  
  /**
   * Add a new component type to the factory. This method throws an exception
   * if the class cannot be resolved. The name of the component IS NOT
   * verified to allow component implementations to be overridden.
   * @param name
   * @param cls
   * @throws ClassNotFoundException
   */
  public synchronized void add(String name, Class<?> cls) {
	  
	  if(locked) {
		  throw new IllegalStateException("Component factory is locked. Components cannot be added");
	  }
    supported.put(name, cls);
    //add name to end of order vector
    if(!order.contains(name))
    	order.addElement(name);
  }

  /**
   * Get a new instance of a supported component.
   * @param name The name of the component; for example "3des-cbc"
   * @return the newly instantiated object
   * @throws ClassNotFoundException
   */
  public Object getInstance(String name) throws SshException {
    if (supported.containsKey(name)) {
      try {
        return createInstance(name, (Class<?>) supported.get(name));
      }
      catch (Throwable t) {
        throw new SshException(t.getMessage(), SshException.INTERNAL_ERROR);
      }
    }
	throw new SshException(name + " is not supported", SshException.UNSUPPORTED_ALGORITHM);
  }

  /**
   * Override this method to create an instance of the component.
   * @param cls
   * @return the newly instantiated object
   * @throws java.lang.Throwable
   */
  protected Object createInstance(String name, Class<?> cls) throws Throwable {
	  return cls.newInstance();
  }

  /**
   * Create a delimited list of supported components.
   * @param preferred
   * @return a comma delimited list
   */
  private synchronized String createDelimitedList(String preferred) {
    StringBuffer listBuf=new StringBuffer();
    int prefIndex=order.indexOf(preferred);
    //remove preferred and add it back at the end to ensure it is not duplicated in the list returned
	if(prefIndex!=-1) {
		listBuf.append(preferred);
	}
    
    for(int i=0;i<order.size();i++) {
    	if(prefIndex==i) {
    		continue;
    	}
		listBuf.append(","+(String) order.elementAt(i));
    }

    if(prefIndex==-1 && listBuf.length()>0) {
    	return listBuf.toString().substring(1);
    }
	return listBuf.toString();    
  }

  /**
   * Remove a supported component
   * @param name
   */
  public synchronized void remove(String name) {
    supported.remove(name);
    //remove name from order vector
    order.removeElement(name);
  }

  /**
   * Clear all of the entries in this component factory.
   */
  public synchronized void clear() {
	  
	  if(locked) {
		  throw new IllegalStateException("Component factory is locked. Removing all components renders it unusable");
	  }
	  
      supported.clear();
      //clear order vector
      order.removeAllElements();
  }

  public Object clone() {
	  ComponentFactory clone=new ComponentFactory(type);
	  clone.order=(Vector<Object>) order.clone();
	  clone.supported=(Hashtable<String, Class<?>>) supported.clone();
	  clone.locked=locked;
	  return clone;
  }

	public String[] toArray() {
		return (String[])order.toArray(new String[order.size()]);
	}


	public void lockComponents() {
		this.locked = true;
	}
  
}
