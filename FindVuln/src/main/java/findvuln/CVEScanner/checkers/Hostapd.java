package findvuln.CVEScanner.checkers;

import java.util.List;

public class Hostapd extends Checker{

	public Hostapd(){
		super();
		this.CONTAINS_PATTERNS = List.of();
		this.FILENAME_PATTERNS = List.of("hostapd");
		this.VERSION_PATTERNS  = List.of("hostapd v([0-9]+\\.[0-9]+)");
		this.VENDOR_PRODUCT    = List.of("w1.fi", "hostapd");
	}
	
}