package com.Illomio;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;

import org.junit.jupiter.api.Test;

class FirewallTest {

	@Test
	void testAccept_packet() throws IOException {
		Firewall fw = new Firewall( "/Users/ridhigulati/Downloads/SampleCSVFile_11kb.csv");
		
		boolean result1 = fw.accept_packet("inbound", "tcp", 80, "192.168.1.2") ;
		assertTrue(result1);
		
		boolean result2 = fw.accept_packet("inbound", "udp", 53, "192.168.2.1") ;
		assertTrue(result2);
		
		boolean result3 = fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11") ;
		assertTrue(result3);
		
		boolean result4 = fw.accept_packet("inbound", "tcp", 81, "192.168.1.2") ;
		assertFalse(result4);
		
		boolean result5 = fw.accept_packet("inbound", "udp", 24, "52.12.48.92") ;
		assertFalse(result5);
		

	}

}
