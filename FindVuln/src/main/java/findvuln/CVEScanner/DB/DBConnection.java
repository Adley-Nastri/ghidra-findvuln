<<<<<<< HEAD
package findvuln.CVEScanner.DB;

import java.io.FileNotFoundException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg; 

public class DBConnection {
	
	
	String location;
	public Connection connection;
	
	public DBConnection (String inputLocation){
		
		ResourceFile rf = null;
		try {
			rf = Application.getModuleFile("FindVuln", inputLocation);
			
			
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		Msg.error(this, rf.getAbsolutePath());
		location = rf.getAbsolutePath();
		
		try {
			connection = DriverManager.getConnection("jdbc:sqlite:"+location);
			
			
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			System.err.println(e.getMessage());
		}
		
		
	}

}
=======
package findvuln.CVEScanner.DB;

import java.io.FileNotFoundException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg; 

public class DBConnection {
	
	
	String location;
	public Connection connection;
	
	public DBConnection (String inputLocation){
		
		ResourceFile rf = null;
		try {
			rf = Application.getModuleFile("FindVuln", inputLocation);
			
			//Msg.error(this, rf.getAbsolutePath());
			
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		Msg.error(this, rf.getAbsolutePath());
		location = rf.getAbsolutePath();
		
		try {
			connection = DriverManager.getConnection("jdbc:sqlite:"+location);
			
			var thingxD = connection;
			Msg.error(this, "CONNECTION IS OKAY?");
			
			/*
			 * Statement statement = connection.createStatement();
			 * statement.setQueryTimeout(15);
			 * 
			 * ResultSet rs = statement.executeQuery("SELECT * FROM cve_range LIMIT 3");
			 * 
			 * 
			 * while (rs.next()) {
			 * 
			 * System.out.println("cve_number = "+ rs.getString("cve_number"));
			 * System.out.println("vendor = "+ rs.getString("vendor"));
			 * System.out.println("product = "+ rs.getString("product"));
			 * System.out.println("version = "+ rs.getString("version")); }
			 */
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			System.err.println(e.getMessage());
		}
		/*
		 * finally { try { if(connection != null) connection.close(); }
		 * catch(SQLException e) { // connection close failed.
		 * System.err.println(e.getMessage()); } }
		 */
		
	}
	
	

}
>>>>>>> parent of 2816ddd (clean up)
