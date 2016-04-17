package org.mksmart.datahub.keyauth;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Properties;
import java.io.FileInputStream;

public class KeyAuth {

    private String host, DB, user, password;
    private int port;

    private Connection conn = null;

    public KeyAuth(String host, int port, String DB, String user, String password) throws KeyAuthException {
	this.host     = host;
	this.port     = port;
	this.DB       = DB;
	this.user     = user;
	this.password = password;	
	try {
	    Class.forName("com.mysql.jdbc.Driver").newInstance();
	    conn = DriverManager.getConnection(
					       "jdbc:mysql://"+host+":"+port+"/"+DB+"?" +
					       "user="+user+"&password="+password);
	} catch (Exception e){
	    throw new KeyAuthException("Can't connect to database", e);
	}
    }

    public boolean grant(User user1, User user, String resourceID, Right right) throws KeyAuthException {	
	if (!authorize(user1, resourceID, Right.GRANT)) {
	    throw new KeyAuthException("User no allowed to grant rights");
	}
	PreparedStatement stmt = null;
	ResultSet rs = null;
	try {
	    stmt = generateInsertQuery(user, resourceID, right);
	    return stmt.execute();
	}
	catch (SQLException ex){
	    throw new KeyAuthException("Cannot check authorisation", ex);
	}
	finally {
	    if (rs != null) {try {rs.close();} catch (SQLException sqlEx) { } rs = null;}
	    if (stmt != null) {try {stmt.close();} catch (SQLException sqlEx) { } stmt = null;}
	}
    }

    public boolean authorize(User user, String resourceID, Right right) throws KeyAuthException {
	PreparedStatement stmt = null;
	ResultSet rs = null;
	try {
	    stmt = generateTestQuery(user, resourceID, right);
	    rs = stmt.executeQuery();
	    return rs.next(); // true if non empty result set
	}
	catch (SQLException ex){
	    throw new KeyAuthException("Cannot check authorisation", ex);
	}
	finally {
	    if (rs != null) {try {rs.close();} catch (SQLException sqlEx) { } rs = null;}
	    if (stmt != null) {try {stmt.close();} catch (SQLException sqlEx) { } stmt = null;}
	}
    }

    private PreparedStatement generateTestQuery(User user, String resourceID, Right right) throws SQLException {	
	String q = "select ukey from rights where ( ukey = ? OR ukey = '*' ) AND ( referrer = '*'  OR referrer = ?  ) AND ( IP = '*' OR IP = ? ) AND ( uright = '*' OR uright = ? ) AND (rID = '*' OR rID = ?)";
	PreparedStatement ps = conn.prepareStatement(q);
	ps.setString(1, user.getKey());
	if (user.getReferrer()!=null) ps.setString(2, user.getReferrer());
	else ps.setString(2, "*");
	if (user.getIP()!=null) ps.setString(3, user.getIP());
	else ps.setString(3, "*");
	ps.setString(4, right.toString());
	if (resourceID!=null) ps.setString(5, resourceID);
	else ps.setString(5, "*");
	return ps;
    }

    private PreparedStatement generateInsertQuery(User user, String resourceID, Right right) throws SQLException {	
	String q = "insert into rights (ukey, referrer, IP, uright, rID) values (?,?,?,?,?)";
	PreparedStatement ps = conn.prepareStatement(q);
	ps.setString(1, user.getKey());
	if (user.getReferrer()!=null) ps.setString(2, user.getReferrer());
	else ps.setString(2, "*");
	if (user.getIP()!=null) ps.setString(3, user.getIP());
	else ps.setString(3, "*");
	ps.setString(4, right.toString());
	if (resourceID!=null) ps.setString(5, resourceID);
	else ps.setString(5, "*");
	return ps;
    }
    
    public static void main(String [] args){
	try{
	    System.err.println("=========== TESTING KEYAUTH ==========");
	    Properties testProps = new Properties();
	    FileInputStream in = new FileInputStream("testProperties");
	    testProps.load(in);
	    in.close();
	    
	    String host = testProps.getProperty("host");
	    String port = testProps.getProperty("port");
	    String DB   = testProps.getProperty("DB");
	    String user = testProps.getProperty("user");
	    String password = testProps.getProperty("password");
	    
	    System.err.println("Connecting to "+host+":"+port+"/"+DB+"?u="+user+":"+password);
	    
	    KeyAuth ka = new KeyAuth(host, Integer.parseInt(port), DB, user, password);

	    if (args[0].equals("grant")){
		String key1 = args[1];
		String key  = args[2];
		String r    = args[3];
		Right  rr = null;
		if (args[4].equals("write")) rr = Right.WRITE;
		if (args[4].equals("read"))  rr = Right.READ;
		if (args[4].equals("grant")) rr = Right.GRANT;
		User u1 = new User(key1);
		User u  = new User(key);
		System.out.println(ka.grant(u1,u,r,rr));
	    } else if (args[0].equals("check")){
		String key = args[1];
		String r   = args[2];
		Right rr = null;
		if (args[3].equals("write")) rr = Right.WRITE;
		if (args[3].equals("read"))  rr = Right.READ;
		if (args[3].equals("grant")) rr = Right.GRANT;
		User u = new User(key);
		System.out.println(ka.authorize(u, r, rr));
	    }	    
	} catch (Exception e){
	    e.printStackTrace();
	}
    }

}
