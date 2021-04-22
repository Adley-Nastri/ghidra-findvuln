package findvuln.CVEScanner.checkers;

import java.util.List;

public class Curl extends Checker{
	
	public Curl(){
		super();
		this.CONTAINS_PATTERNS = List.of();
		this.FILENAME_PATTERNS = List.of("curl");
		this.VERSION_PATTERNS  = List.of("curl ([678]+\\.[0-9]+\\.[0-9]+)");
		this.VENDOR_PRODUCT    = List.of("haxx", "curl");
	}
	
}