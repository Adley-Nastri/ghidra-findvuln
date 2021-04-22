package findvuln.CVEScanner.checkers;

import java.util.List;

public class Openssl extends Checker{
	
	public Openssl(){
		super();
		this.CONTAINS_PATTERNS = List.of("part of OpenSSL", "openssl.cnf", "-DOPENSSL_");
		this.FILENAME_PATTERNS = List.of("libssl.so", "libcrypto.so");
		this.VERSION_PATTERNS  = List.of("part of OpenSSL ([01]+\\.[0-9]+\\.[0-9]+[a-z]*) ","OpenSSL ([01]+\\.[0-9]+\\.[0-9]+[a-z]*) ");
		this.VENDOR_PRODUCT    = List.of("openssl", "openssl");
	}
	
}