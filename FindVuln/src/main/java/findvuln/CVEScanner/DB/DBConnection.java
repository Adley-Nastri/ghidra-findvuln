package findvuln.CVEScanner.DB;

import java.io.FileNotFoundException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
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
