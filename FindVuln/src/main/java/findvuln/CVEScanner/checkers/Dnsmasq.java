package findvuln.CVEScanner.checkers;

import java.util.List;

public class Dnsmasq extends Checker {
	
	public Dnsmasq(){
		super();
		this.CONTAINS_PATTERNS = List.of("Dnsmasq is lightweight, easy to configure DNS forwarder and DHCP server\\.\\neither in each host or in a central configuration file\\.");
		this.FILENAME_PATTERNS = List.of("dnsmasq");
		this.VERSION_PATTERNS  = List.of("dnsmasq-([0-9]+\\.[0-9]+)");
		this.VENDOR_PRODUCT    = List.of("dnsmasq", "dnsmasq");	
	}

}