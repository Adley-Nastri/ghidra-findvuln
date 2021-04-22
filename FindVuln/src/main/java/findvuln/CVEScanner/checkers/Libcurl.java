package findvuln.CVEScanner.checkers;

import java.util.List;

public class Libcurl extends Checker{
	
	public Libcurl(){
		super();
		this.CONTAINS_PATTERNS = List.of("An unknown option was passed in to libcurl", "A requested feature, protocol or option was not found built-in in this libcurl due to a build-time decision.","CLIENT libcurl 7.");
		this.FILENAME_PATTERNS = List.of("libcurl.so.");
		this.VERSION_PATTERNS  = List.of("CLIENT libcurl ([678]+\\.[0-9]+\\.[0-9]+)");
		this.VENDOR_PRODUCT    = List.of("haxx", "libcurl");
	}
	
}