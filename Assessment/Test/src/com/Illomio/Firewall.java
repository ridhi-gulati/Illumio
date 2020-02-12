package com.Illomio;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;


import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.Mongo;

//import com.mongodb.MongoClient;
//import com.mongodb.client.MongoDatabase;

public class Firewall {
	
	//Path of the Rule File
	private String path;
	
	@SuppressWarnings("deprecation")
	//Connection with mongoDB with localhost
	Mongo mongo = new Mongo("127.0.0.1", 27017);
	
	@SuppressWarnings("deprecation")
	//Get the Database "Firewall"
	DB db = mongo.getDB("Firewall");
	
	//Get the Collection "Rules"
	DBCollection collection = db.getCollection("rules");
	
	/***
	 * Constructor to get the file path and read the file
	 * @param path
	 * @throws IOException
	 */
	public Firewall (String path) throws IOException {
		this.path = path;
		readFile();
	}

	/***
	 * This function will read all the rules present in the file and store them in the mongoDB database
	 * 
	 * @param:
	 * @return: void
	 * @throws IOException 
	 */
	private void readFile() throws IOException {
		BufferedReader br = null;
		FileReader fr = null;
		
		try {
			//Reading the File
			fr = new  FileReader(this.path);
			br = new BufferedReader(fr);
			String line;
			
			while((line = br.readLine()) !=null) {
				String currentLine [] = line.split(",");
				
				//If the port contains range, then each entry of the port is saved separately as a document
				if (currentLine[2].contains("-")){
					
					String limit[] = currentLine[2].split("-");
					int lowerLimit= Integer.parseInt(limit[0]);
					int upperLimit= Integer.parseInt(limit[1]);
					
					for (int i = lowerLimit; i <= upperLimit; i++) {
						
						//Inserting Document in a database
						//Assuming that first column is direction, followed by protocol, port and ip_address
						BasicDBObject document = new BasicDBObject();
						document.put("direction", currentLine[0]);
						document.put("protocol", currentLine[1]);
						document.put("port", String.valueOf(i));
						document.put("ip_address", currentLine[3]);
						collection.insert(document);
						continue;	
					}
					continue;
				}	
				else {
					
					//Assuming that first column is direction, followed by protocol, port and ip_address
					BasicDBObject document = new BasicDBObject();
					document.put("direction", currentLine[0]);
					document.put("protocol", currentLine[1]);
					document.put("port", currentLine[2]);
					document.put("ip_address", currentLine[3]);
					collection.insert(document);
					continue;
				}	
			}	
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		finally {
			//Closing Resources
			br.close();
			fr.close();
		}
	}
	/***
	 * This function converts ip address to long
	 * 
	 * @param: ip_address
	 * @return: long [Converted address to long]
	 */
	private long ipToLong (String ip) {
		String address[] = ip.split("\\.");
		long answer = 0;
		for(int i=0; i < address.length; i++) {
			int pow = 3 - i; // "3" as there are four partitions and i starts from 0->3
			int number = Integer.parseInt(address[i]);
			//Converting to long
			answer += number * Math.pow(256, pow);
		}	
		return answer;
	}

	/***
	 * This function returns if the packet is accepted or not
	 * 
	 * @param: direction: String
	 * @param: protocol: String
	 * @param: port: int
	 * @param: ip_address: String
	 * @return: boolean [Whether the packet is accepted or rejected]
	 */
	public boolean accept_packet(String direction, String protocol, int port, String ip_address) {
		
		// Get the document from the database which is equal to the direction, port and protocol 
		BasicDBObject criteria = new BasicDBObject();
		criteria.put("direction", direction);
		criteria.put("protocol", protocol);
		criteria.put("port", String.valueOf(port));
		DBCursor cursor = collection.find(criteria);
		
		// After obtaining the result, look for the ip_address and check against the ip_address passed as parameter.
		// This step is done as ip_address are stored as range also, 
		// and if the passes value is between the range this step will look for that ip_address.
		while(cursor.hasNext()) {
			String ip = cursor.next().get("ip_address").toString();
			
			//If the ip_address returned has a range then check between the range
			if(ip.contains("-")) {
				String limit [] = ip.split("-");
				
				//Convert ip address to long
				long lowerLimit= ipToLong(limit[0]);
 				long upperLimit= ipToLong(limit[1]);
 				long original_ip = ipToLong(ip_address);
 		
 				if(original_ip >= lowerLimit && original_ip <= upperLimit) {
 					return true;
 				}	
			}
			// Else if there is no range check with the returned address.
			 if(ip.equals(ip_address)) {
				return true;
			}
		}	
		//If nothing is present then return false
		return false;
	}
	
	@SuppressWarnings("unused")
	public static void main (String args[]) throws IOException {
		String filePath = "/Users/ridhigulati/Downloads/SampleCSVFile_11kb.csv";
		Firewall fw = new Firewall(filePath);
		boolean check = fw.accept_packet("outbound", "tcp", 1, "192.168.10.11");
	}

}
