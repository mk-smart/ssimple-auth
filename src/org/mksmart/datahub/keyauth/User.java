package org.mksmart.datahub.keyauth;

public class User {

    private String key, referrer, IP;

    public User(String key, String IP, String referrer){
	this.key = key;
	this.IP  = IP;
	this.referrer = referrer;
    }

    public User(String key, String IP){
	this.key = key;
	this.IP  = IP;
    }

    public User(String key){
	this.key = key;
    }

    public void setKey(String key){
	this.key = key;
    }
    
    public String getKey(){
	return key;
    }

    public void setIP(String IP){
	this.IP = IP;
    }
    
    public String getIP(){
	return IP;
    }

    public void setReferrer(String referrer){
	this.referrer = referrer;
    }
    
    public String getReferrer(){
	return referrer;
    }

    public String toString(){
	return key+";;"+referrer+";;"+IP;
    }

}
