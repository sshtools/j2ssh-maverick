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
package com.sshtools.events;

/**
 * Interface to be implemented by an event service implementation.
 */
public interface EventService {

	/**
	 * Add a MaverickListener to the list of objects that will be sent
	 * MaverickEvents.
	 * 
	 * @param listener
	 *            listener to add
	 */
	public void addListener(EventListener listener);

	/**
	 * Add a MaverickListener to the list of objects that will be sent
	 * MaverickEvents.
	 * 
	 * @param listener
	 *            listener to add
	 */
	public void addListener(String threadPrefix, EventListener listener);

	/**
	 * Remove a MaverickListener from the list of objects that will be sent
	 * MaverickEventss.
	 * 
	 * @param listener
	 *            listener to remove
	 */
	public void removeListener(String threadPrefix);

	/**
	 * Fire a MaverickEvent at all MaverickListeners that have registered an
	 * interest in events.
	 * 
	 * @param evt
	 *            event to fire to all listener
	 */
	public void fireEvent(Event evt);
}
