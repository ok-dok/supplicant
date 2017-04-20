/**

 * Title: Supplicant.java

 * CopyRight: CopyRight © 52debug.cc

 * @author Shawn_Hou

 * 2017年4月16日 下午9:31:11
 
 * Description: 安朗小蝴蝶拨号认证客户端 v1.0
 
 * Github地址：https://github.com/shawn-hou/supplicant
 
 * git clone https://github.com/shawn-hou/supplicant.git

 * Bug Report: shawn_hou@163.com

 */


import java.io.File;

import java.io.FileInputStream;

import java.io.FileOutputStream;

import java.io.IOException;

import java.io.InputStreamReader;

import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;

import java.net.DatagramSocket;

import java.net.InetAddress;

import java.net.InterfaceAddress;

import java.net.NetworkInterface;

import java.net.SocketException;
import java.net.URLDecoder;
import java.net.UnknownHostException;

import java.security.MessageDigest;

import java.util.Arrays;

import java.util.Enumeration;

import java.util.Iterator;

import java.util.List;

import java.util.Properties;


public class Supplicant {

	private static String configFile = "";

	private static String USERNAME = "";

	private static String PASSWORD = "";

	private static String HOST_IP = "";

	private static String MAC_ADDR = "";

	private static String LOCAL_IP = "";

	private static String SERVICE_TYPE = "internet";

	private static String DHCP_SETTING = "0";

	private static String CLIENT_VERSION = "3.8.2";
	
	private static String IS_CHANGE = "true";

	private static int index = 0x01000000;

	private static byte[] block = {0x2a, 0x06, 0, 0, 0, 0, 0x2b, 0x06, 0, 0, 0, 0, 0x2c, 0x06, 0, 0, 0,

			0, 0x2d, 0x06, 0, 0, 0, 0, 0x2e, 0x06, 0, 0, 0, 0, 0x2f, 0x06, 0, 0, 0, 0};

	

	private DatagramSocket udpSocket;



	public static void main(String args[]) {

		Supplicant supplicant = new Supplicant();
		
		String path = supplicant.getClass().getResource("/").getFile();
		
		try {
			
			configFile = URLDecoder.decode(path, "utf-8") + "config.properties";
			
		} catch (UnsupportedEncodingException e) {
			
			e.printStackTrace();
			
		}

		for(int i=0; i<args.length; i++){

			if(args[i] .equals("-c")){

				if(args[i+1] != null && !args[i+1].isEmpty()){

					configFile = args[i+1];

				}else{

					System.out.println("Please give the config file path behind -c.");

					return ;

				}

			}

		}

		boolean flag = true;
		
		try {
			
			supplicant.loadData(args);
			
		} catch (Exception e) {
			
			System.out.println(e.getMessage());

			flag = false;
		}
		
		if(flag){
			
			supplicant.run();
			
		}

	}



	private void loadData(String[] args) throws Exception {

		Properties properties = new Properties();

		InputStreamReader reader = null;

		OutputStreamWriter writer = null;

		try{

			File file = new File(configFile);

			if(!file.exists()){

				file.createNewFile();
				
				reader = new InputStreamReader(new FileInputStream(file),"utf-8");
				
				properties.load(reader);
				
				properties.setProperty("username", USERNAME);

				properties.setProperty("password", PASSWORD);

				properties.setProperty("server_ip", HOST_IP);

				properties.setProperty("local_ip", LOCAL_IP);

				properties.setProperty("mac_addr", MAC_ADDR);

				properties.setProperty("service", SERVICE_TYPE);

				properties.setProperty("dhcp", DHCP_SETTING);

				properties.setProperty("client_version", CLIENT_VERSION);

				properties.setProperty("is_change", IS_CHANGE);

				writer = new OutputStreamWriter(new FileOutputStream(file),"utf-8");
				
				properties.store(writer, "Supplicant Config File");
				
			}else{
				
				reader = new InputStreamReader(new FileInputStream(file),"utf-8");
				
				properties.load(reader);
			}
			
			USERNAME = properties.getProperty("username");

			PASSWORD = properties.getProperty("password");

			HOST_IP = properties.getProperty("server_ip");

			LOCAL_IP = properties.getProperty("local_ip");

			MAC_ADDR = properties.getProperty("mac_addr");

			SERVICE_TYPE = properties.getProperty("service");

			DHCP_SETTING = properties.getProperty("dhcp");

			CLIENT_VERSION = properties.getProperty("client_version");

			IS_CHANGE = properties.getProperty("is_change");

			if(isNullOrBlank(IS_CHANGE) || !IS_CHANGE.equals("false")){

				IS_CHANGE = "true";

			}

			if(isNullOrBlank(USERNAME) || isNullOrBlank(PASSWORD)){

				USERNAME = "";

				PASSWORD = "";

				for(int i=0; i<args.length; i++){

					if(args[i].equals("-u")){

						USERNAME = args[i+1].trim();

						if(isNullOrBlank(USERNAME)){

							throw new Exception("Failed to get username behind -u.");

						}

					}

					if(args[i].equals("-p")){

						PASSWORD = args[i+1].trim();

						if(isNullOrBlank(PASSWORD)){

							throw new Exception("Failed to get password bihind -p.");

						}

					}

				}

				if(isNullOrBlank(USERNAME) || isNullOrBlank(PASSWORD)){

					throw new Exception("Username or password connot be empty.");

				}

				IS_CHANGE = "true";

			}
			
			if(isNullOrBlank(LOCAL_IP) || isNullOrBlank(MAC_ADDR)){

				LOCAL_IP = "";

				MAC_ADDR = "";

				try {

					autoGetMacIp();

				} catch (SocketException e) {

					throw new Exception("Failed to get network card information.\n"

							+ "Rerun the program to try again or edit the config.properties "

							+ "file to fill in the 'mac_addr' and 'local_ip' field.");

				}

				if(isNullOrBlank(LOCAL_IP) || isNullOrBlank(MAC_ADDR)){

					throw new Exception("Failed to get network card information.\n"

							+ "Rerun the program to try again or edit the config.properties "

							+ "file to fill in the 'mac_addr' and 'local_ip' field.");

				}

				IS_CHANGE = "true";

			}

			if(!checkNetwork()){
				
				throw new Exception("The network card is not available, "
						
						+ "please check whether the network card is disabled?");
			}
			
			initUdpSocket();

			if(isNullOrBlank(HOST_IP)){

				HOST_IP = "";

				searchServerIp();

				IS_CHANGE = "true";

			}

			if(isNullOrBlank(SERVICE_TYPE)){

				SERVICE_TYPE = "";

				searchService();

				IS_CHANGE = "true";

			}

			if(isNullOrBlank(DHCP_SETTING)){

				DHCP_SETTING = "0";

				IS_CHANGE = "true";

			}

			if(isNullOrBlank(CLIENT_VERSION)){

				CLIENT_VERSION = "3.8.2";

				IS_CHANGE = "true";

			}

			if(IS_CHANGE.equals("true")){

				properties.setProperty("username", USERNAME);

				properties.setProperty("password", PASSWORD);

				properties.setProperty("server_ip", HOST_IP);

				properties.setProperty("local_ip", LOCAL_IP);

				properties.setProperty("mac_addr", MAC_ADDR);

				properties.setProperty("service", SERVICE_TYPE);

				properties.setProperty("dhcp", DHCP_SETTING);

				properties.setProperty("client_version", CLIENT_VERSION);

				properties.setProperty("is_change", "false");
				
				writer = new OutputStreamWriter(new FileOutputStream(file),"utf-8");

				properties.store(writer, "Supplicant Config File");	

			}

			System.out.println("Service :\t" + SERVICE_TYPE);

			System.out.println("Server IP:\t" + HOST_IP);

			System.out.println("Local IP:\t" + LOCAL_IP);

			System.out.println("Mac Addr:\t" + MAC_ADDR);

			System.out.println("Username:\t" + USERNAME);

			//System.out.println("Password:\t" + PASSWORD);

			System.out.println();

		} catch (IOException e) {
			
			throw new Exception("Failed to load the config file \"" + configFile + "\".");

		}finally{

			if(reader != null){

				try {

					reader.close();

				} catch (IOException e) {

					e.printStackTrace();

				}

			}

			if(writer != null){

				try {

					writer.close();

				} catch (IOException e) {

					e.printStackTrace();

				}

			}

		}

	}



	public Supplicant(){

	}

	

	public void run(){

		byte[] packet = generateUpnetPacket();

		byte[] session = connect(packet);

		if(session != null){

			try {

				boolean status = breathe(session);

				if(!status){

					System.out.println("You have been disconnected. Try to reconnect...");

					disConnect(session);

					run();

				}

			} catch (InterruptedException e) {

				System.out.println("You have been disconnected.");

				disConnect(session);

				udpSocket.close();

			}

		}else{

			System.out.println("Request connection authentication failure.");
			
			udpSocket.close();

		}

	}

	

	/**

	 * 创建udp套接字

	 */

	private void initUdpSocket(){

		if(udpSocket == null){

			try {

				udpSocket = new DatagramSocket(3848);

				udpSocket.setReuseAddress(true);

				udpSocket.setSoTimeout(5000);

			} catch (SocketException e) {

				System.out.println("Failed to bind socket to port:3848.\n"

						+ "Please check whether the port is being used(netstat -apn | grep 3848)?");

				System.exit(0);

			}

		}

	}



	private void disConnect(byte[] session){

		byte[] downnetPacket = generateDownnetPacket(session);

		InetAddress address = null;

		try {

			address = InetAddress.getByName(HOST_IP);

		} catch (UnknownHostException e) {

			e.printStackTrace();

		}

		DatagramPacket datagramPacket = new DatagramPacket(downnetPacket, downnetPacket.length, address, 3848);

		try {

			udpSocket.send(datagramPacket);

		} catch (IOException e) {

			//e.printStackTrace();

		}

	}

	/**

	 * 创建请求下线的packet

	 * @param session

	 * @return

	 */

	private byte[] generateDownnetPacket(byte[] session){

		int packet_len = session.length + 88;

		byte[] packet = new byte[packet_len];

		byte i = -1;

		

		packet[++i] = 0x05;

		packet[++i] = (byte)packet_len;

		for(; i<17; ){

			packet[++i] = 0;

		}

		packet[++i] = 0x08;

		packet[++i] = (byte) (session.length + 2);

		for (byte b : session) {

			packet[++i] = b;

		}

		

		packet[++i] = 0x09;

		packet[++i] = 0x12;

		byte[] bytes = LOCAL_IP.getBytes();

		for (byte b : bytes) {

			packet[++i] = b;

		}

		for(int j=0; j<16-bytes.length; j++){

			packet[++i] = 0;

		}

		

		packet[++i] = 0x07;

		packet[++i] = 0x08;

		String[] macs = MAC_ADDR.split(":");

		for (String str : macs) {

			packet[++i] = (byte)Integer.parseInt(str,16);

		}

		

		packet[++i] = 0x14;

		packet[++i] = 0x06;

		String indexStr = String.format("%x", index);

		int indexLen = indexStr.length();

		packet[++i] = (byte)Integer.parseInt(indexStr.substring(0, indexLen-6),16);

		packet[++i] = (byte)Integer.parseInt(indexStr.substring(indexLen-6, indexLen-4),16);

		packet[++i] = (byte)Integer.parseInt(indexStr.substring(indexLen-4, indexLen-2),16);

		packet[++i] = (byte)Integer.parseInt(indexStr.substring(indexLen-2, indexLen-0),16);

		

		for (byte b : block) {

			packet[++i] = b;

		}



		byte[] md5Bytes = getMD5Bytes(packet);

		for(int j=0; j<md5Bytes.length; j++){

			packet[j+2] = md5Bytes[j];

		}

		packet = encrypt(packet);

		return packet;

	}

	

	/**

	 * 保持在线

	 * @param session

	 * @return

	 * @throws InterruptedException

	 */

	private boolean breathe(byte[] session) throws InterruptedException{

		Thread.sleep(1000);

		while(true){

			byte[] breathePacket = generateBreathePacket(session);

			InetAddress address = null;

			try {

				address = InetAddress.getByName(HOST_IP);

			} catch (UnknownHostException e) {

				e.printStackTrace();

			}

			DatagramPacket datagramPacket = new DatagramPacket(breathePacket, breathePacket.length, address, 3848);

			try {

				udpSocket.send(datagramPacket);

				byte[] buffer = new byte[4096];

				DatagramPacket dp = new DatagramPacket(buffer, 0, buffer.length);

				udpSocket.receive(dp);

				int bufferSize = dp.getLength();

				byte[] recvPacket = decrypt(Arrays.copyOf(buffer, bufferSize));

				byte[] recvMd5 = new byte[16];

				for(int j=2; j<18; j++){

					recvMd5[j-2] = recvPacket[j];

					recvPacket[j] = 0;

				}

				if(checkMD5(recvMd5, getMD5Bytes(recvPacket))){

					byte status = recvPacket[20];

					if(status == 0)

						return false;

				}else{

					return false;

				}

			} catch (IOException e) {

				return false;

			}

			index += 3;

			Thread.sleep(20000);

		}

	}

	

	/**

	 * 创建保持在线的packet

	 * @param session

	 * @return

	 */

	private byte[] generateBreathePacket(byte[] session){

		int packet_len = session.length + 88;

		byte[] packet = new byte[packet_len];

		byte i = -1;

		
		packet[++i] = 0x03;

		packet[++i] = (byte)packet_len;

		for(; i<17; ){

			packet[++i] = 0;

		}



		packet[++i] = 0x08;

		packet[++i] = (byte) (session.length + 2);

		for (byte b : session) {

			packet[++i] = b;

		}

		

		packet[++i] = 0x09;

		packet[++i] = 0x12;

		byte[] bytes = LOCAL_IP.getBytes();

		for (byte b : bytes) {

			packet[++i] = b;

		}

		for(int j=0; j<16-bytes.length; j++){

			packet[++i] = 0;

		}

		

		packet[++i] = 0x07;

		packet[++i] = 0x08;

		String[] macs = MAC_ADDR.split(":");

		for (String str : macs) {

			packet[++i] = (byte)Integer.parseInt(str,16);

		}

		

		packet[++i] = 0x14;

		packet[++i] = 0x06;

		String indexStr = String.format("%x", index);

		int indexLen = indexStr.length();

		packet[++i] = (byte)Integer.parseInt(indexStr.substring(0, indexLen-6),16);

		packet[++i] = (byte)Integer.parseInt(indexStr.substring(indexLen-6, indexLen-4),16);

		packet[++i] = (byte)Integer.parseInt(indexStr.substring(indexLen-4, indexLen-2),16);

		packet[++i] = (byte)Integer.parseInt(indexStr.substring(indexLen-2, indexLen-0),16);

		

		for (byte b : block) {

			packet[++i] = b;

		}



		byte[] md5Bytes = getMD5Bytes(packet);

		for(int j=0; j<md5Bytes.length; j++){

			packet[j+2] = md5Bytes[j];

		}

		packet = encrypt(packet);

		return packet;

	}

	

	/**

	 * 进行连接认证

	 * @param packet

	 * @return

	 */

	private byte[] connect(byte[] packet){

		InetAddress address = null;

		try {

			address = InetAddress.getByName(HOST_IP);

		} catch (UnknownHostException e) {

			e.printStackTrace();

		}

		DatagramPacket datagramPacket = new DatagramPacket(packet, packet.length, address, 3848);

		

		try{

			udpSocket.send(datagramPacket);

			byte[] buffer = new byte[4096];

			DatagramPacket dp = new DatagramPacket(buffer, 0, buffer.length);

			udpSocket.receive(dp);

			int bufferSize = dp.getLength();

			

			byte[] recvPacket = decrypt(Arrays.copyOf(buffer, bufferSize));

			

			byte[] recvMd5 = new byte[16];

			for(int j=2; j<18; j++){

				recvMd5[j-2] = recvPacket[j];

				recvPacket[j] = 0;

			}

			

			if(checkMD5(recvMd5, getMD5Bytes(recvPacket))){

				byte status = recvPacket[20];

				int sessionLen = recvPacket[22];

				byte[] session = new byte[sessionLen];

				for(short i=0,j=23; j<sessionLen+23; i++,j++){

					session[i] = recvPacket[j];

					recvPacket[j] = 0;

				}

				int messageIndex = -1;

				for(int j=sessionLen+23; j<recvPacket.length; j++){

					if(recvPacket[j] == 11){

						messageIndex = j;

						break;

					}

				}

				int messageLen = recvPacket[messageIndex+1] & 0xff;

				byte[] message = new byte[messageLen];

				for(int i=0,j=messageIndex+2; j<messageIndex+2+messageLen; i++,j++){

					message[i] = recvPacket[j];

				}

				String msg = new String(message,"gbk");

				System.out.println(msg);

				if(status == 0)

					return null;

				else

					return session;

			}else{

				System.out.println("Connect failed. Try Reconnecting...");

				return connect(packet);

			}

		} catch (IOException e) {

			System.out.println(e.getMessage()+".");

		}

		return null;

	}

	

	/**

	 * 创建连接网络packet

	 */

	private byte[] generateUpnetPacket(){

		int packet_len = 38 + USERNAME.length() + PASSWORD.length() + LOCAL_IP.length() 

			+ SERVICE_TYPE.length() + DHCP_SETTING.length() + CLIENT_VERSION.length();

		byte[] packet = new byte[packet_len];

		byte i = -1;

		

		packet[++i] = 0x01;

		packet[++i] = (byte)packet_len;

		for(; i<17; ){

			packet[++i] = 0;

		}

		

		packet[++i] = 0x07;

		packet[++i] = 0x08;

		String[] macs = MAC_ADDR.split(":");

		for (String str : macs) {

			packet[++i] = (byte)Integer.parseInt(str,16);

		}

		

		packet[++i] = 0x01;

		packet[++i] = (byte) (USERNAME.length() + 2);

		for(byte b : USERNAME.getBytes()){

			packet[++i] = b;

		}

		

		packet[++i] = 0x02;

		packet[++i] = (byte) (PASSWORD.length() + 2);

		for(byte b : PASSWORD.getBytes()){

			packet[++i] = b;

		}

		

		packet[++i] = 0x09;

		packet[++i] = (byte) (LOCAL_IP.length() + 2);

		for(byte b : LOCAL_IP.getBytes()){

			packet[++i] = b;

		}

		

		packet[++i] = 0x0a;

		packet[++i] = (byte) (SERVICE_TYPE.length() + 2);

		for(byte b : SERVICE_TYPE.getBytes()){

			packet[++i] = b;

		}

		

		packet[++i] = 0x0e;

		packet[++i] = (byte) (DHCP_SETTING.length() + 2);

		for(char c : DHCP_SETTING.toCharArray()){

			packet[++i] = (byte)Integer.parseInt(c+"");

		}

		

		packet[++i] = 0x1f;

		packet[++i] = (byte) (CLIENT_VERSION.length() + 2);

		for(byte b : CLIENT_VERSION.getBytes()){

			packet[++i] = b;

		}

		

		byte[] md5Bytes = getMD5Bytes(packet);

		for(int j=0; j<md5Bytes.length; j++){

			packet[j+2] = md5Bytes[j];

		}

		packet = encrypt(packet);

		return packet;

	}

	/**

	 * 查找Internet服务

	 */

	private void searchService() {

		byte packet_len = 1 + 1 + 16 + 1 + 1 + 5 + 1 + 1 + 6;

		byte[] packet = new byte[packet_len];

		byte i = -1;

		

		packet[++i] = 0x07;

		packet[++i] = packet_len;

		for(; i<17; ){

			packet[++i] = 0;

		}

		

		packet[++i] = 0x08;

		packet[++i] = 0x07;

		for(byte j=0; j<5; j++){

			packet[++i] = j;

		}

		

		packet[++i] = 0x07;

		packet[++i] = 0x08;

		String[] macs = MAC_ADDR.split(":");

		for (String str : macs) {

			packet[++i] = (byte)Integer.parseInt(str,16);

		}

		

		byte[] md5Bytes = getMD5Bytes(packet);

		for(int j=0; j<md5Bytes.length; j++){

			packet[j+2] = md5Bytes[j];

		}

		

		packet = encrypt(packet);

		

		InetAddress address = null;

		try {

			address = InetAddress.getByName(HOST_IP);

		} catch (UnknownHostException e) {

			e.printStackTrace();

		}

		DatagramPacket datagramPacket = new DatagramPacket(packet, packet.length, address, 3848);

		

		try{

			udpSocket.send(datagramPacket);

			byte[] buffer = new byte[1024];

			DatagramPacket dp = new DatagramPacket(buffer, 0, buffer.length);

			udpSocket.receive(dp);

			int bufferSize = dp.getLength();

			byte[] recvPacket = decrypt(Arrays.copyOf(buffer, bufferSize));

			

			byte[] recvMd5 = new byte[16];

			for(int j=2; j<18; j++){

				recvMd5[j-2] = recvPacket[j];

				recvPacket[j] = 0;

			}

						

			if(checkMD5(recvMd5, getMD5Bytes(recvPacket))){

				//查找服务index

				short serviceIndex = -1;

				for(short j=0; j<recvPacket.length; j++){

					if(recvPacket[j] == 10){

						serviceIndex = j;

						break;

					}

				}

				SERVICE_TYPE = "";

				//取出服务内容

				if(serviceIndex != -1){

					int serviceLen = recvPacket[serviceIndex+1];

					for(int j=serviceIndex+2; j<serviceIndex+serviceLen; j++){

						SERVICE_TYPE += (char)(recvPacket[j] & 0xff);

					}

				}else{

					System.out.println("Failed to search service. Retrying...");

					searchService();

				}

			}else{

				System.out.println("Failed to search service. Retrying...");

				searchService();

			}

		} catch (SocketException e1) {

			System.out.println("Failed to search service： Server no response!");

			System.exit(0);

			//e1.printStackTrace();

		} catch (IOException e) {

			System.out.println("Failed to search service： Server no response!");

			System.exit(0);

			//e.printStackTrace();

		}

	}

	

	/**

	 * 搜寻服务器ip地址

	 */

	private void searchServerIp(){

		byte packet_len = 1 + 1 + 16 + 1 + 1 + 5 + 1 + 1 + 16 + 1 + 1 + 6;

		byte[] packet = new byte[packet_len];

		byte i=-1;

		packet[++i] = 0x0c;

		packet[++i] = packet_len;

		for(; i<17; ){

			packet[++i] = 0;

		}

		

		packet[++i] = 0x08;

		packet[++i] = 0x07;

		for(byte j=0; j<5; j++){

			packet[++i] = j;

		}

		

		packet[++i] = 0x09;

		packet[++i] = 0x12;

		byte[] bytes = LOCAL_IP.getBytes();

		for (byte b : bytes) {

			packet[++i] = b;

		}

		for(int j=0; j<16-bytes.length; j++){

			packet[++i] = 0;

		}

		

		packet[++i] = 0x07;

		packet[++i] = 0x08;

		String[] macs = MAC_ADDR.split(":");

		for (String str : macs) {

			packet[++i] = (byte)Integer.parseInt(str,16);

		}

		byte[] md5Bytes = getMD5Bytes(packet);

		for(int j=0; j<md5Bytes.length; j++){

			packet[j+2] = md5Bytes[j];

		}

		

		packet = encrypt(packet);

		

		InetAddress address = null;

		try {

			address = InetAddress.getByName("1.1.1.8");

		} catch (UnknownHostException e) {

			e.printStackTrace();

		}

		

		DatagramPacket datagramPacket = new DatagramPacket(packet, packet.length, address, 3850);

		try{

			udpSocket.send(datagramPacket);

			byte[] buffer = new byte[1024];

			DatagramPacket dp = new DatagramPacket(buffer, 0, buffer.length);

			udpSocket.receive(dp);

			int bufferSize = dp.getLength();

			byte[] recvPacket = decrypt(Arrays.copyOf(buffer, bufferSize));

			

			//print(recvPacket);

			

			byte[] recvMd5 = new byte[16];

			for(int j=2; j<18; j++){

				recvMd5[j-2] = recvPacket[j];

				recvPacket[j] = 0;

			}

			

			if(checkMD5(recvMd5, getMD5Bytes(recvPacket))){

				//查找服务器地址的index

				short serverIndex = -1;

				for(short j=0; j<recvPacket.length; j++){

					if(recvPacket[j] == 0x0c){

						serverIndex = j;

						break;

					}

				}

				HOST_IP = "";

				//取出服务器ip地址

				if(serverIndex != -1){

					int serverLen = recvPacket[serverIndex+1];

					for(int j=serverIndex+2; j<serverIndex+serverLen; j++){

						HOST_IP += (recvPacket[j] & 0xff) + ".";

					}

					HOST_IP = HOST_IP.substring(0, HOST_IP.length()-1);

				}else{

					System.out.println("Failed to search server ip. Retrying...");

					searchServerIp();

				}

			}else{

				System.out.println("Failed to search server ip. Retrying...");

				searchServerIp();

			}

		} catch (SocketException e1) {

			System.out.println("Failed to search server ip: Server no response!");

			System.exit(0);

			//e1.printStackTrace();

		} catch (IOException e) {

			System.out.println("Failed to search server ip: Server no response!");

			System.exit(0);

			//e.printStackTrace();

		}

		

	}

	

	/**

	 * md5校验

	 * @param arg0

	 * @param arg1

	 * @return

	 */

	private boolean checkMD5(byte[] arg0, byte[] arg1){

		boolean flag = true;

		for(int i=0; i<arg0.length; i++){

			if(arg0[i] != arg1[i]){

				flag = false;

				break;

			}

		}

		return flag;

	}

	/**
	 * 检查网卡是否可用
	 * @return 如果可用返回true，不可用则返回false
	 */
	private boolean checkNetwork(){
		
		try {
			
			Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();

			while (en.hasMoreElements()) {

				NetworkInterface ni = en.nextElement();

				byte[] bytes = ni.getHardwareAddress();
				
				String displayName = ni.getDisplayName();
				
				if(displayName.contains("Virtual") || displayName.contains("virtual"))

					continue;

				if (ni.isUp() && ni != null && bytes != null && bytes.length == 6) {

					List<InterfaceAddress> list = ni.getInterfaceAddresses();
					
					if(!list.isEmpty()){
						
						return true;
						
					}
					
					System.out.println(list.get(0).getAddress().getHostAddress().toString());
				}
			}
		} catch (SocketException e) {
			
			return false;
			
		}
		
		return false;
	}
	

	/**

	 * 自动获取mac、ip地址

	 * @throws SocketException

	 */

	private void autoGetMacIp() throws SocketException {

		Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();

		while (en.hasMoreElements()) {

			NetworkInterface ni = en.nextElement();

			byte[] bytes = ni.getHardwareAddress();

			if (ni.isUp() && ni != null && bytes != null && bytes.length == 6) {

				String displayName = ni.getDisplayName();

				if(displayName.contains("Wireless") || displayName.contains("wireless") 

						|| displayName.contains("Virtual") || displayName.contains("virtual"))

					continue;

				//System.out.println(displayName);

				StringBuffer sb = new StringBuffer();

				for (byte b : bytes) {

					// 与11110000作按位与运算以便读取当前字节高4位

					sb.append(Integer.toHexString((b & 240) >> 4));

					// 与00001111作按位与运算以便读取当前字节低4位

					sb.append(Integer.toHexString(b & 15));

					sb.append(":");

				}

				sb.deleteCharAt(sb.length() - 1);

				MAC_ADDR = sb.toString().toUpperCase();

				//System.out.println(MAC_ADDR);

				List<InterfaceAddress> list = ni.getInterfaceAddresses();

				Iterator<InterfaceAddress> it = list.iterator();

				while (it.hasNext()) {

					InterfaceAddress ia = it.next();

					String ip = ia.getAddress().toString().split("/")[1];

					if (ip.length() < 16){

						LOCAL_IP = ip;

						//System.out.println(ip);

					}

				}



			}

		}

	}

	public static void print(byte[] packet){

		System.out.print('[');

		for (int i=0; i<packet.length; i++) {

			if(i < packet.length-1)

				System.out.print((int)packet[i]+", ");

			else

				System.out.print((int)packet[i]);

		}

		System.out.println(']');

		System.out.print('[');

		for (int i=0; i<packet.length; i++) {

			if(i < packet.length-1)

				System.out.print(Integer.toHexString(packet[i])+", ");

			else

				System.out.print(Integer.toHexString(packet[i]));

		}

		System.out.println(']');

	}

	public static void print(short[] packet){

		System.out.print('[');

		for (int i=0; i<packet.length; i++) {

			if(i < packet.length-1)

				System.out.print((int)packet[i]+", ");

			else

				System.out.print((int)packet[i]);

		}

		System.out.println(']');

		System.out.print('[');

		for (int i=0; i<packet.length; i++) {

			if(i < packet.length-1)

				System.out.print(Integer.toHexString(packet[i])+", ");

			else

				System.out.print(Integer.toHexString(packet[i]));

		}

		System.out.println(']');

	}

    /**

     * 对byte数组进行MD5摘要计算，返回加密后的16进制字符串

     *

     * @param str

     * @return

     */

	private String getMD5(byte[] byteArray) {

		MessageDigest md5 = null;

		try {

			md5 = MessageDigest.getInstance("MD5");

		} catch (Exception e) {

			System.out.println(e.toString());

			e.printStackTrace();

			return "";

		}

		byte[] md5Bytes = md5.digest(byteArray);

		StringBuffer hexValue = new StringBuffer();

		for (int i = 0; i < md5Bytes.length; i++) {

			int val = ((int) md5Bytes[i]) & 0xff;

			if (val < 16)

				hexValue.append("0");

			hexValue.append(Integer.toHexString(val));

		}

		return hexValue.toString();

	}

	

	/**

	 * 对byte数组直接进行摘要计算，返回加密后的byte数组

	 * @param byteArray

	 * @return

	 */

	private byte[] getMD5Bytes(byte[] byteArray) {

		MessageDigest md5 = null;

		try {

			md5 = MessageDigest.getInstance("MD5");

		} catch (Exception e) {

			System.out.println(e.toString());

			e.printStackTrace();

			return null;

		}

		byte[] md5Bytes = md5.digest(byteArray);

		

		return md5Bytes;

	}

	

	/**

	 * 加密

	 * @param packet

	 * @return

	 */

	private byte[] encrypt(byte[] packet){

	    byte[] encrypt_packet = new byte[packet.length];

	    int i=0;

	    for (byte b : packet) {

			encrypt_packet[i++] = (byte)(

				(b & 0x80) >> 6 | (b & 0x40) >> 4 | (b & 0x20) >> 2 | (b & 0x10) << 2 | 

				(b & 0x08) << 2 | (b & 0x04) << 2 | (b & 0x02) >> 1 | (b & 0x01) << 7 );

		}

	   return encrypt_packet;

	}

	/**

	 * 解密

	 * @param packet

	 * @return

	 */

	private byte[] decrypt(byte[] packet){

		byte[] decrypt_packet = new byte[packet.length];

		int i=0;

	    for (byte b : packet) {

			decrypt_packet[i++] = (byte)(

				(b & 0x80) >> 7 | (b & 0x40) >> 2 | (b & 0x20) >> 2 | (b & 0x10) >> 2 | 

				(b & 0x08) << 2 | (b & 0x04) << 4 | (b & 0x02) << 6 | (b & 0x01) << 1 );

		}

	    return decrypt_packet;

	}



	public static boolean isNullOrBlank(String str){

		if(str == null || "".equals(str.trim()) || str.isEmpty())

			return true;

		return false;

	}

}

