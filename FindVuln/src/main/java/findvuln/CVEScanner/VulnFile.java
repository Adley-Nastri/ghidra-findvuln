package findvuln.CVEScanner;

import java.util.LinkedList;
import java.util.List;

public class VulnFile {
	
	public String filepath;
	public String version;
	public List<String> cve_list = new LinkedList<String>();

	
	
	public VulnFile(String filePath, String fileVersion, List<String> cveList) {
		
		this.filepath = filePath;
		this.version = fileVersion;
		this.cve_list = cveList;
		
	}

	
}
