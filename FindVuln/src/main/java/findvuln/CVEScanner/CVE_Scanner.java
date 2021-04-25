package findvuln.CVEScanner;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import findvuln.CVEScanner.checkers.Busybox;
import findvuln.CVEScanner.checkers.Checker;
import findvuln.CVEScanner.checkers.Curl;
import findvuln.CVEScanner.checkers.Hostapd;
import findvuln.CVEScanner.checkers.Libcurl;
import findvuln.CVEScanner.versioning.DefaultArtifactVersion;
import ghidra.util.Msg;
import findvuln.CVEScanner.DB.DBConnection;


public class CVE_Scanner {

	
	
	static DBConnection dbConnection = new DBConnection("data/cve.db");
	static Connection conn = dbConnection.connection;
	//Step 1 Gather binaries
    //Step 2 Parse binaries
    //Step 3 Scan versions
    //Step 4 Cross reference CVE data from database
	
	public static HashMap<String, VulnFile> cve_map = new HashMap<String, VulnFile>();
	
	
	
	
	
	
	public static Connection main(File rootFolder) throws SQLException, IOException {
		
		
		
		Checker[] checkers = {new Busybox(), new Curl(), new Libcurl(), new Hostapd()};
		
		walk(rootFolder.getAbsolutePath(), checkers);
		
		
		return conn;
		
	}
	

	
	
	
	public static void getCVEs(File file, Checker checker, String[] scan_array) throws IOException, SQLException {
		
		
		

		
		
		
		
		var checker_version = checker.get_version(scan_array, file.getName()); 
		
		
		
		
		
		if (!checker_version.get("version").equals("UNKNOWN")) {
			
			String this_file = "This file " +checker_version.get("is_or_contains") + " " + checker.VENDOR_PRODUCT.get(1);
			
			
			Msg.info(CVE_Scanner.class, this_file);
			
			
			String version_ = "Version : "+checker_version.get("version");
			
			
			Msg.info(CVE_Scanner.class, version_);
			
			
			
			Statement statement = conn.createStatement();
			statement.setQueryTimeout(5);
			
			
			
			List<String> cve_list = new LinkedList<String>();
			
			
			String query_any_marked = String.format("SELECT CVE_number FROM cve_range "
					+ "WHERE vendor = '%s' AND product = '%s' AND version = '%s'"
					
					,checker.VENDOR_PRODUCT.get(0),
					checker.VENDOR_PRODUCT.get(1),
					checker_version.get("version"));
			
			
			
			ResultSet rs1 = statement.executeQuery(query_any_marked);
			
			
			while (rs1.next()) {
				
				cve_list.add(rs1.getString("cve_number"));
			}
			
			
			
			
			
			
			String query_any_range = String.format("SELECT cve_number, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding FROM cve_range "
					+ "WHERE vendor = '%s' AND product = '%s' AND version = '%s'"
					
					,checker.VENDOR_PRODUCT.get(0),
					checker.VENDOR_PRODUCT.get(1),
					"*");
			
			
			ResultSet rs2 = statement.executeQuery(query_any_range);
			
			
	
			
			while (rs2.next()) {
				
				
				DefaultArtifactVersion parsed_version = new DefaultArtifactVersion(checker_version.get("version"));
				
				String cve_number = rs2.getString(1);
				String versionStartIncluding = rs2.getString(2);
				String versionStartExcluding = rs2.getString(3);
				
				String versionEndIncluding = rs2.getString(4);
				String versionEndExcluding = rs2.getString(5);
				
				
				
				
				DefaultArtifactVersion VSI = new DefaultArtifactVersion(versionStartIncluding);
				DefaultArtifactVersion VSE = new DefaultArtifactVersion(versionStartExcluding);
				
				DefaultArtifactVersion VEI = new DefaultArtifactVersion(versionEndIncluding);
				DefaultArtifactVersion VEE = new DefaultArtifactVersion(versionEndExcluding);
				
				
				
				
				///check start range
				boolean passes_start = false;
				
				
				if(!versionStartIncluding.equals("") && parsed_version.compareTo(VSI) >= 0 ) {
					
					
					passes_start = true;
				}
				
				
				if(!versionStartExcluding.equals("") && parsed_version.compareTo(VSE) > 0 ) {
					
					
					passes_start = true;
				}
				
				
				if(versionStartIncluding.equals("") && versionStartExcluding.equals("")) {
					
					passes_start = true;
				}     
				
				
				
				
				///check end range
				boolean passes_end = false;
				
				if(!versionEndIncluding.equals("") && parsed_version.compareTo(VEI) <= 0) {
					
					
						
						passes_end = true;
						
					
				}
				
				
				if(!versionEndExcluding.equals("") && parsed_version.compareTo(VEE) < 0) {
					
					
						
						passes_end = true;
					
				
				}
				
				
				if(versionEndIncluding.equals("") && versionEndExcluding.equals("")) {
					
					passes_end = true;
				}
				
				
				
				
				if(passes_start && passes_end) {
					cve_list.add(cve_number);
				}
				
			}
			
			
			for (var item : cve_list) {
				Msg.debug(CVE_Scanner.class, item);
			}
			
			
			
			
			
			
			VulnFile vulnFile = new VulnFile(file.getAbsolutePath(), checker_version.get("version"), cve_list);
			
			
			
			
			cve_map.put(checker.VENDOR_PRODUCT.get(1), vulnFile);
			
			String cve_size = "\n"+cve_list.size() + " CVEs";
			
			Msg.info(CVE_Scanner.class,cve_size +"\n");
			
			

			
			
		}
		else {
			String file_not_type = "File is not of type '" + checker.VENDOR_PRODUCT.get(1)+"'";
			
			Msg.info(CVE_Scanner.class, file_not_type);
		}
		
		
	}
	
	private static void walk(String path, Checker[] checkers) throws IOException, SQLException {

		File root = new File(path);
		File[] list = root.listFiles();

		if (list == null)
			return;
		
		

		for (File f : list) {
			if (f.isDirectory() || !Files.exists(f.toPath())) {
				walk(f.getPath(), checkers);
				
			} else {
				
				
				
				Msg.info(CVE_Scanner.class ,f.getAbsoluteFile());
				
				
				String[] scan_file_arr = scan_file(f);
				
				
				
				for(Checker checker : checkers) {
					getCVEs(f, checker, scan_file_arr);
				}
				
				System.out.println();
				Msg.info(CVE_Scanner.class ,"\n");
			}
		}
	}
	
	public static String[] scan_file(File file) throws IOException {
		
		
	
		
		String[] strings_arr = Util.Strings(file);
		
		
		return strings_arr;
		
		
	}
	
	
	
}
	
	
