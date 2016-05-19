package org.mksmart.datahub.keyauth;

import java.io.FileInputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Properties;

/**
 * Simple authentication methods based on key and optionally referrers and IP, based on a very simple MySQL
 * database
 * 
 * Requires a table "rights" created through 
 * create table rights ( 
 *    id int(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY, 
 *    ukey varchar(128) NOT NULL, 
 *    referrer varchar(256), 
 *    IP varchar(128), 
 *    uright varchar(30) NOT NULL, 
 *    rID varchar(256) 
 *  );
 * 
 * @author mdaquin
 **/

public class KeyAuth {

    public static void main(String[] args) {
        try {
            System.err.println("=========== TESTING KEYAUTH ==========");
            Properties testProps = new Properties();
            FileInputStream in = new FileInputStream("testProperties");
            testProps.load(in);
            in.close();

            String host = testProps.getProperty("host");
            String port = testProps.getProperty("port");
            String DB = testProps.getProperty("DB");
            String user = testProps.getProperty("user");
            String password = testProps.getProperty("password");

            System.err.println("Connecting to " + host + ":" + port + "/" + DB + "?u=" + user + ":"
                               + password);

            KeyAuth ka = new KeyAuth(host, Integer.parseInt(port), DB, user, password);

            if (args[0].equals("grant")) {
                String key1 = args[1];
                String key = args[2];
                String r = args[3];
                Right rr = null;
                if (args[4].equals("write")) rr = Right.WRITE;
                if (args[4].equals("read")) rr = Right.READ;
                if (args[4].equals("grant")) rr = Right.GRANT;
                User u1 = new User(key1);
                User u = new User(key);
                System.out.println(ka.grant(u1, u, r, rr));
            } else if (args[0].equals("check")) {
                String key = args[1];
                String r = args[2];
                Right rr = null;
                if (args[3].equals("write")) rr = Right.WRITE;
                if (args[3].equals("read")) rr = Right.READ;
                if (args[3].equals("grant")) rr = Right.GRANT;
                User u = new User(key);
                System.out.println(ka.authorize(u, r, rr));
            } else if (args[0].equals("list")) {
                String key = args[1];
                Right rr = null;
                if (args[2].equals("write")) rr = Right.WRITE;
                if (args[2].equals("read")) rr = Right.READ;
                if (args[2].equals("grant")) rr = Right.GRANT;
                User u = new User(key);
                String[] rs = ka.listResourcesWithRight(u, rr);
                for (String r : rs)
                    System.out.println("- " + r);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private String host, DB, user, password;

    private int port;

    public KeyAuth(String host, int port, String DB, String user, String password) throws KeyAuthException {
        this.host = host;
        this.port = port;
        this.DB = DB;
        this.user = user;
        this.password = password;
    }

    public boolean authorize(User user, String resourceID, Right right) throws KeyAuthException {
        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            conn = setUp();
            stmt = generateTestQuery(user, resourceID, right, conn);
            rs = stmt.executeQuery();
            return rs.next(); // true if non empty result set
        } catch (SQLException ex) {
            throw new KeyAuthException("Cannot check authorisation", ex);
        } finally {
            tearDown(conn, stmt, rs);
        }
    }

    private PreparedStatement generateInsertQuery(User user, String resourceID, Right right, Connection conn) throws SQLException {
        String q = "insert into rights (ukey, referrer, IP, uright, rID) values (?,?,?,?,?)";
        PreparedStatement ps = conn.prepareStatement(q);
        ps.setString(1, user.getKey());
        if (user.getReferrer() != null) ps.setString(2, user.getReferrer());
        else ps.setString(2, "*");
        if (user.getIP() != null) ps.setString(3, user.getIP());
        else ps.setString(3, "*");
        ps.setString(4, right.toString());
        if (resourceID != null) ps.setString(5, resourceID);
        else ps.setString(5, "*");
        return ps;
    }

    private PreparedStatement generateListQuery(User user, Right right, Connection conn) throws SQLException {
        String q = "select distinct rID from rights where ( ukey = ? OR ukey = '*' ) AND ( referrer = '*'  OR referrer = ?  ) AND ( IP = '*' OR IP = ? ) AND ( uright = '*' OR uright = ? )";
        PreparedStatement ps = conn.prepareStatement(q);
        ps.setString(1, user.getKey());
        if (user.getReferrer() != null) ps.setString(2, user.getReferrer());
        else ps.setString(2, "*");
        if (user.getIP() != null) ps.setString(3, user.getIP());
        else ps.setString(3, "*");
        ps.setString(4, right.toString());
        return ps;
    }

    private PreparedStatement generateTestQuery(User user, String resourceID, Right right, Connection conn) throws SQLException {
        String q = "select distinct ukey from rights where ( ukey = ? OR ukey = '*' ) AND ( referrer = '*'  OR referrer = ?  ) AND ( IP = '*' OR IP = ? ) AND ( uright = '*' OR uright = ? ) AND (rID = '*' OR rID = ?)";
        PreparedStatement ps = conn.prepareStatement(q);
        ps.setString(1, user.getKey());
        if (user.getReferrer() != null) ps.setString(2, user.getReferrer());
        else ps.setString(2, "*");
        if (user.getIP() != null) ps.setString(3, user.getIP());
        else ps.setString(3, "*");
        ps.setString(4, right.toString());
        if (resourceID != null) ps.setString(5, resourceID);
        else ps.setString(5, "*");
        return ps;
    }

    public boolean grant(User user1, User user, String resourceID, Right right) throws KeyAuthException {
        if (!authorize(user1, resourceID, Right.GRANT)) {
            throw new KeyAuthException("User no allowed to grant rights");
        }
        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            conn = setUp();
            stmt = generateInsertQuery(user, resourceID, right, conn);
            return stmt.execute();
        } catch (SQLException ex) {
            throw new KeyAuthException("Cannot check authorisation", ex);
        } finally {
            tearDown(conn, stmt, rs);
        }
    }

    public String[] listResourcesWithRight(User user, Right right) throws KeyAuthException {
        ArrayList<String> results = new ArrayList<String>();
        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            conn = setUp();
            stmt = generateListQuery(user, right, conn);
            rs = stmt.executeQuery();
            while (rs.next()) {
                results.add(rs.getString(1));
            }
            return results.toArray(new String[results.size()]);
        } catch (SQLException ex) {
            throw new KeyAuthException("Cannot check authorisation", ex);
        } finally {
            tearDown(conn, stmt, rs);
        }
    }

    protected Connection setUp() throws SQLException {
        try {
            String driver = "com.mysql.jdbc.Driver";
            Class.forName(driver);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("No MySQL JDBC driver found.", e);
        }
        String strConn = "jdbc:mysql://" + this.host + (this.port > 0 ? "" : (':' + this.port)) + "/"
                         + this.DB + "?" + "user=" + this.user + "&password=" + this.password;
        return DriverManager.getConnection(strConn);
    }

    protected void tearDown(Connection conn, PreparedStatement stmt, ResultSet rs) throws KeyAuthException {
        if (rs != null) {
            try {
                rs.close();
            } catch (SQLException sqlEx) {
                System.err.println("WARN - Failed to close MySQL result set."
                                   + " Will attempt to close connection anyway.");
            }
            rs = null;
        }
        if (stmt != null) {
            try {
                stmt.close();
            } catch (SQLException sqlEx) {
                System.err.println("WARN - Failed to close MySQL prepared statement."
                                   + " Will attempt to close connection anyway.");
            }
            stmt = null;
        }
        if (conn != null) try {
            conn.close();
        } catch (SQLException e) {
            throw new KeyAuthException(
                    "Could not close MySQL connection for authorisation checking."
                            + " This may have repercussions on subsequent database connection attempts", e);
        }
    }

}
