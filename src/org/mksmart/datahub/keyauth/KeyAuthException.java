package org.mksmart.datahub.keyauth;

public class KeyAuthException extends Exception {
    public KeyAuthException() { 
	super(); 
    }

    public KeyAuthException(String message) { 
	super(message); 
    }

    public KeyAuthException(String message, Throwable cause) { 
	super(message, cause); 
    }

    public KeyAuthException(Throwable cause) { 
	super(cause); 
    }
}
