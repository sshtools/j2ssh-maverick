package com.sshtools.events;

/**
 * Interface to be implemented by an event service implementation.
 */
public interface EventService {
    
	/**
     * Add a MaverickListener to the list of objects that will be sent MaverickEvents.
     * 
     * @param listener listener to add
     */
    public void addListener(EventListener listener);
	
    /**
     * Add a MaverickListener to the list of objects that will be sent MaverickEvents.
     * 
     * @param listener listener to add
     */
    public void addListener(String threadPrefix, EventListener listener);

    /**
     * Remove a MaverickListener from the list of objects that will be sent MaverickEventss.
     * 
     * @param listener listener to remove
     */
    public void removeListener(String threadPrefix);
    
    /**
     * Fire a MaverickEvent at all MaverickListeners that have registered an interest in events.
     * @param evt event to fire to all listener
     */
    public void fireEvent(Event evt);
}
