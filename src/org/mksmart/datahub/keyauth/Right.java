package org.mksmart.datahub.keyauth;

public class Right {

    private String label;

    public static final Right READ  = new Right("READ");
    public static final Right WRITE = new Right("WRITE");
    public static final Right GRANT = new Right("GRANT");

    private Right(String label){
	this.label = label;
    }

    public String toString(){
	return label;
    }

}
