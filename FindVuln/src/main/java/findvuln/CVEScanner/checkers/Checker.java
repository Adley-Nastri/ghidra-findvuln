package findvuln.CVEScanner.checkers;


import java.util.ArrayList;


import java.util.HashMap;
import java.util.List;

import java.util.regex.*;

import findvuln.CVEScanner.Util;


public class Checker {
	
	
	public List<String> CONTAINS_PATTERNS = new ArrayList<String>();
	
	public List<String> VERSION_PATTERNS = new ArrayList<String>();
	
	public List<String> FILENAME_PATTERNS = new ArrayList<String>();
	
	public List<String> VENDOR_PRODUCT= new ArrayList<String>();
	
	
	
	@SuppressWarnings("unlikely-arg-type")
	public HashMap<String, String> get_version(String lines[], String filename) {
		
		
		HashMap<String, String> version_info = new HashMap<String, String>();

			for (var pattern : FILENAME_PATTERNS) {
				Pattern pat = Pattern.compile(pattern);
				
				//String index_of = filename.get(filename.indexOf(pattern));
				
				
				Matcher mat = pat.matcher(filename);
				
				//String mpp = mat.pattern().pattern();
				
				//String www = "";
				
				boolean anyMatch = FILENAME_PATTERNS.stream().anyMatch(str -> str.equals(filename));
				
				
				if(anyMatch) {
					
					
					//
					String str = "thing found";
					//System.out.println(str);
					version_info.put("is_or_contains", "is");
				}
			}
			
			if (!version_info.containsKey("is_or_contains") && !guess_contains(lines)) {
				
				version_info.put("is_or_contains", "contains");
			}
		
			if (version_info.containsKey("is_or_contains")) {
				version_info.put("version", Util.regex_find(lines,this.VERSION_PATTERNS));
			}
		
		
		return version_info;
	}
	
	@SuppressWarnings("unlikely-arg-type")
	private Boolean guess_contains(String[] lines) {

		
		for (String line : lines) {
			
			for (var pattern : this.CONTAINS_PATTERNS) {
				
				Pattern pat = Pattern.compile(pattern);
				Matcher mat = pat.matcher(line);
				
				if(CONTAINS_PATTERNS.contains(mat.find())){
					return true;
				}
				
			}
			
			
		}
		
		return false;
		
	}

	
	
}
