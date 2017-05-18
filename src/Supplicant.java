
/**

 * Title: Supplicant.java

 * CopyRight: CopyRight © 52debug.cc

 * @author Shawn_Hou

 * 2017年4月16日 下午9:31:11
 
 * Description: 安朗小蝴蝶拨号认证客户端 v2.0
 
 * Github地址：https://github.com/shawn-hou/supplicant
 
 * git clone https://github.com/shawn-hou/supplicant.git

 * Bug Report: shawn_hou@163.com

 */
import java.io.Console;
import java.io.File;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
import java.util.Scanner;

import sun.security.util.Password;

public class Supplicant {
	/**
	 * 账户
	 */
	public static String USERNAME = "";
	/**
	 * 密码
	 */
	public static String PASSWORD = "";
	/**
	 * 服务器主机ip地址
	 */
	public static String HOST_IP = "";
	/**
	 * 认证主机物理网卡地址
	 */
	public static String MAC_ADDR = "";
	/**
	 * 认证主机ip地址
	 */
	public static String LOCAL_IP = "";
	/**
	 * 服务类型，默认为internet
	 */
	public static String SERVICE_TYPE = "internet";
	/**
	 * dhcp(自动获取)标志，默认为0
	 */
	public static String DHCP_SETTING = "0";
	/**
	 * 小蝴蝶版本号，默认为3.8.2
	 */
	public static String CLIENT_VERSION = "3.8.2";
	/**
	 * 是否允许重连标志，true为允许，false为不允许
	 */
	public static String RECONNECT_ENABLE = "true";
	/**
	 * 是否允许打印服务器通知信息，默认为true
	 */
	public static String DISPLAY_MESSAGE = "true";
	/**
	 * 配置文件路径
	 */
	public String configFile = "";
	/**
	 * 标识配置信息是否发生改变
	 */
	private boolean isChange = false;
	/**
	 * 标识是否控制台输入配置信息
	 */
	public boolean consoleRead = false;	
	/**
	 * 连接状态
	 */
	public Status status = Status.LOGOUT;
	/**
	 * 统计重连次数，当RECONNECT_ENABLE = "true"时有效
	 */
	public int retryCnt = 0;
	/**
	 * 最大重连次数，默认为5
	 */
	public int retryMax = 5;
	private static int index = 0x01000000;
	private static byte[] block = { 0x2a, 0x06, 0, 0, 0, 0, 0x2b, 0x06, 0, 0, 0, 0, 0x2c, 0x06, 0, 0, 0, 0, 0x2d, 0x06,
			0, 0, 0, 0, 0x2e, 0x06, 0, 0, 0, 0, 0x2f, 0x06, 0, 0, 0, 0 };
	private DatagramSocket udpSocket;
	
	private enum Status{
		/**
		 * 认证错误
		 */
		LOGIN_ERROR,
		/**
		 * 认证超时
		 */
		LOGIN_TIMEOUT,
		/**
		 * 认证MD5校验失败
		 */
		LOGIN_MD5ERROR,
		/**
		 * 在线
		 */
		ONLINE,
		/**
		 * 下线
		 */
		LOGOUT,
		/**
		 * 保持呼吸超时
		 */
		BREATHE_TIMEOUT,
		/**
		 * 保持呼吸MD5出错
		 */
		BREATHE_MD5ERROR, 
		/**
		 * 保持呼吸出错
		 */
		BREATHE_ERROR
	}

	public static void main(String args[]) {
		Supplicant supplicant = new Supplicant();
		
		try {
			supplicant.readArgs(args);	//读取输入参数，isChange = true
			if(supplicant.consoleRead){
				supplicant.readDataFromConsole();		//从控制台读入配置信息，isChange = true
			}else{
				supplicant.readDataFromProperties();	//从配置文件读入配置信息，如果配置文件信息为空，则通过控制台读入
			}
			
		} catch (Exception e) {	//读取配置信息出错，退出程序
			System.out.println(e.getMessage());
			System.exit(0);
		}
		
		supplicant.run();
		
	}
	
	/**
	 * 程序运行入口，线程阻塞
	 */
	public void run(){
		try {
			initUdpSocket();
		} catch (Exception e) {
			System.out.println(e.getMessage());
			System.exit(0);
		}		
		boolean flag = true;
		while (flag) {
			connect();
			switch(this.status){
			case LOGIN_ERROR: flag = false;
				break;
			case LOGIN_MD5ERROR:
			case LOGIN_TIMEOUT:
				if (RECONNECT_ENABLE.equals("true")) {
					if (++retryCnt <= retryMax) { // 5次重连机会
						System.out.println("连接超时，重新进行连接认证...");
					} else {
						System.out.println("认证失败：连接超时，请稍后再试！");
						flag = false;
					}
				} else {
					flag = false;
				}
				break;
			case BREATHE_MD5ERROR:
			case BREATHE_ERROR:
			case BREATHE_TIMEOUT:
			case LOGOUT:
				if (RECONNECT_ENABLE.equals("true")) {
					if (++retryCnt <= retryMax) { // 5次重连机会
						System.out.println("保持连接失败！ 重新进行连接认证...");
					} else {
						System.out.println("连接认证失败，请稍后再试！");
						flag = false;
					}
				} else {
					flag = false;
				}
				break;
			default:
				break;
			}
			
		}
		closeUdpSocket();
	}
	
	/**
	 * 读取输入参数
	 * @param args
	 * @throws Exception
	 */
	public void readArgs(String[] args) throws Exception{
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("-c")) {
				if (args[i + 1] != null && !args[i + 1].isEmpty()) {
					configFile = args[i + 1];
					return;
				} else {
					throw new Exception("请在参数'-c'后面给定配置文件的路径及文件名.");
				}
			}
			if(args[i].equals("-i")){
				consoleRead = true;	//从控制台读入配置信息
				return ;
			}
			if (args[i].equals("-u")) {
				USERNAME = args[i + 1].trim();
				if (isNullOrBlank(USERNAME)) {
					throw new Exception("请在参数'-u'后面给定账户名。");
				}
				isChange = true;
			}
			if (args[i].equals("-p")) {
				PASSWORD = args[i + 1].trim();
				if (isNullOrBlank(PASSWORD)) {
					throw new Exception("请在参数'-p'后面给定账户密码。");
				}
				isChange = true;
			}
		}
	}
	
	/**
	 * 从控制台读取配置信息
	 * @throws Exception e.getMessage();获取错误提示信息
	 */
	public void readDataFromConsole() throws Exception {
		Scanner in = new Scanner(System.in);
		System.out.print("认证ip地址: ");
		LOCAL_IP = in.nextLine().trim();
		System.out.print("物理网卡地址: ");
		MAC_ADDR = in.nextLine().trim();
		System.out.print("账户: ");
		USERNAME = in.nextLine().trim();
		System.out.print("密码: ");
		Console console = System.console();
		PASSWORD = new String(console.readPassword());
		initUdpSocket();	//初始化udp Socket
		searchServerIp();	//查找服务器ip地址
		searchService();	//查找服务
		DHCP_SETTING = "0";
		CLIENT_VERSION = "3.8.2";
		System.out.print("是否允许断线重连？([y]/n)");
		String line = in.nextLine();
		if(isNullOrBlank(line) || line.charAt(0) == 'y' || line.charAt(0) == 'Y')
			RECONNECT_ENABLE = "true";
		else
			RECONNECT_ENABLE = "false";
		System.out.print("是否显示通知信息？([y]/n)");
		line = in.nextLine();
		if(isNullOrBlank(line) || line.charAt(0) == 'y' || line.charAt(0) == 'Y')
			DISPLAY_MESSAGE = "true";
		else
			DISPLAY_MESSAGE = "false";
		isChange = true;
		consoleRead = true;
	}
	
	/**
	 * 从配置文件读取配置信息，若配置文件中未读到用户名和密码，则提示通过控制台输入
	 * @throws Exception e.getMessage();获取错误提示信息
	 */
	private void readDataFromProperties() throws Exception {
		Properties properties = new Properties();
		InputStreamReader reader = null;
		try {
			File file = new File(configFile);
			if (file.exists()) {	//如果存在配置文件，则读取相关配置信息
				reader = new InputStreamReader(new FileInputStream(file), "utf-8");
				properties.load(reader);
				if(isNullOrBlank(USERNAME))
					USERNAME = properties.getProperty("username");
				if(isNullOrBlank(PASSWORD))
					PASSWORD = properties.getProperty("password");
				HOST_IP = properties.getProperty("server_ip");
				LOCAL_IP = properties.getProperty("local_ip");
				MAC_ADDR = properties.getProperty("mac_addr");
				SERVICE_TYPE = properties.getProperty("service");
				DHCP_SETTING = properties.getProperty("dhcp");
				CLIENT_VERSION = properties.getProperty("client_version");
				RECONNECT_ENABLE = properties.getProperty("reconnect_enable");
				DISPLAY_MESSAGE = properties.getProperty("display_message");
			}
			//如果没有读入文件配置信息，或者读入的配置文件信息为空，进行下列操作
			if(isNullOrBlank(DISPLAY_MESSAGE) || !DISPLAY_MESSAGE.equals("false")){
				DISPLAY_MESSAGE = "true";
				isChange = true;
			}
			if(isNullOrBlank(RECONNECT_ENABLE) || !RECONNECT_ENABLE.equals("false")){
				RECONNECT_ENABLE = "true";
				isChange = true;
			}
			if (isNullOrBlank(USERNAME) || isNullOrBlank(PASSWORD)) {
				Scanner in = new Scanner(System.in);
				System.out.print("账户: ");
				USERNAME = in.nextLine().trim();
				System.out.print("密码: ");
				Console console = System.console();
				PASSWORD = new String(console.readPassword());
				isChange = true;
			}
			if (isNullOrBlank(LOCAL_IP) || isNullOrBlank(MAC_ADDR)) {
				LOCAL_IP = "";
				MAC_ADDR = "";
				try {
					autoGetMacIp();
				} catch (SocketException e) {
					throw new Exception("获取物理地址和IP地址失败。\n"
							+ "请重新运行程序或者手动修改配置文件里的mac_addr和local_ip两项，填入正确的信息。\n"
							+ "请注意：MAC地址':'需要写做\"\\:\"。 ");
				}
				if (isNullOrBlank(LOCAL_IP) || isNullOrBlank(MAC_ADDR)) {
					throw new Exception("获取物理地址和IP地址失败。\n"
							+ "请重新运行程序或者手动修改配置文件里的mac_addr和local_ip两项，填入正确的信息。\n"
							+ "请注意：MAC地址':'需要写做\"\\:\"。  ");
				}
				isChange = true;
			}
			
			if (isNullOrBlank(HOST_IP) || isNullOrBlank(SERVICE_TYPE)) {
				HOST_IP = "";
				SERVICE_TYPE = "";
				initUdpSocket();	//初始化udp Socket
				searchServerIp();	//查找服务器ip地址
				searchService();	//查找服务
				isChange = true;
			}
			
			if (isNullOrBlank(DHCP_SETTING)) {
				DHCP_SETTING = "0";
				isChange = true;
			}
			if (isNullOrBlank(CLIENT_VERSION)) {
				CLIENT_VERSION = "3.8.2";
				isChange = true;
			}
			System.out.println("-----------------------------------");
			System.out.println("  服务类型:    \t" 	+ SERVICE_TYPE);
			System.out.println("  认证ip地址:  \t" 	+ LOCAL_IP);
			System.out.println("  服务器ip地址:\t" 	+ HOST_IP);
			System.out.println("  物理网卡地址:\t" 	+ MAC_ADDR);
			System.out.println("  账户:      \t" + USERNAME);
			System.out.println("-----------------------------------");
		} catch (IOException e) {
			throw new Exception("加载配置文件 \"" + configFile + "\"失败！");
		} finally {
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	/**
	 * 连接认证成功后，将配置信息保存到配置文件
	 */
	public void saveData(){
		Properties properties = new Properties();
		File file = new File(configFile);
		if(!file.exists()){
			try {
				file.createNewFile();
			} catch (IOException e) {
				System.out.println(e.getMessage());
				System.exit(0);
			}
		}
		properties.setProperty("username", USERNAME);
		properties.setProperty("password", PASSWORD);
		properties.setProperty("server_ip", HOST_IP);
		properties.setProperty("local_ip", LOCAL_IP);
		properties.setProperty("mac_addr", MAC_ADDR);
		properties.setProperty("service", SERVICE_TYPE);
		properties.setProperty("dhcp", DHCP_SETTING);
		properties.setProperty("client_version", CLIENT_VERSION);
		properties.setProperty("reconnect_enable", RECONNECT_ENABLE);
		properties.setProperty("display_message",DISPLAY_MESSAGE);
		OutputStreamWriter writer = null;
		try {
			writer = new OutputStreamWriter(new FileOutputStream(file), "utf-8");
			properties.store(writer, "Supplicant Config File");
		} catch (IOException e) {
			System.out.println(e.getMessage());
			System.exit(0);
		}finally {
			if(writer != null){
				try {
					writer.close();
				} catch (IOException e) {
					System.out.println(e.getMessage());
					System.exit(0);
				}
			}
		}
		
	}

	public Supplicant() {
		try {
			configFile = URLDecoder.decode(System.getProperty("user.dir"), "utf-8")
					+ File.separator + "config.properties";
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 单例模式创建udp套接字
	 * @throws Exception e.getMessage();获取错误提示信息
	 */
	private void initUdpSocket() throws Exception {
		
		if (udpSocket == null || udpSocket.isClosed()) {
			if (!checkNetwork()) {
				throw new Exception("网卡不可用，请检查网卡是否被禁用?");
			}
			try {
				/**
				 * 这里不绑定端口一样能够进行拨号。
				 * 绑定端口是为了防止多个拨号软件同时进行拨号。
				 * 但不绑定端口貌似可以实现多个客户端同时拨不同账号？
				 */
				//udpSocket = new DatagramSocket();
				udpSocket = new DatagramSocket(3848);
				udpSocket.setReuseAddress(true);
				udpSocket.setSoTimeout(5000);
			} catch (SocketException e) {
				throw new Exception("程序初始化失败！请检查端口(3848)是否被占用？");
			}
		}
	}

	/**
	 * 关闭udp套接字
	 */
	private void closeUdpSocket() {
		if (udpSocket != null && !udpSocket.isClosed()) {
			udpSocket.close();
		}
	}


	/**
	 * 连接到internet，线程阻塞。当连接出错或超时，即status=-1或0时，方法执行结束
	 */
	public void connect() {
		status = Status.LOGOUT;
		index = 0x01000000;
		byte[] packet = generateLoginPacket();
		/**
		 * 认证成功 status=ONLINE,同时返回session；
		 * 认证出错 status=LOGIN_ERROR；
		 * 认证超时 status=LOGIN_TIMEOUT
		 * md5校验出错 status=LOGIN_MD5ERROR
		 */
		byte[] session = login(packet);	
		if (session != null) {
			retryCnt = 0;	//每次连接成功以后重连次数重置为0
			System.out.println("您已连接到" + SERVICE_TYPE + "。请保持连接...");
			if(isChange){	//配置信息发生改动
				saveData(); 	//保存配置信息到配置文件
				isChange = false;
			}
			try {
				breathe(session); 	//阻塞，只有当保持连接失败时，才会执行下面的操作，失败时，status值为BREATHE_ERROR或者BREATHE_TIMEOUT
				if (status != Status.ONLINE) { 	// 保持在线失败，请求下线
					logout(session);
				}
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
	}
	
	/**
	 * 进行连接认证。认证成功返回session,同时置status=1;不成功返回null,连接出错置status=-1,超时或md5校验出错置status=0
	 * @param packet 通过generateUpnetPacket();创建得到
	 * @return session 认证成功后，返回byte[]；认证失败，返回null
	 */
	private byte[] login(byte[] packet) {
		InetAddress address = null;
		try {
			address = InetAddress.getByName(HOST_IP);
		} catch (UnknownHostException e) {
			System.out.println(e.getMessage());
			System.exit(0);
		}
		DatagramPacket datagramPacket = new DatagramPacket(packet, packet.length, address, 3848);
		try {
			udpSocket.send(datagramPacket);
			byte[] buffer = new byte[4096];
			DatagramPacket dp = new DatagramPacket(buffer, 0, buffer.length);
			udpSocket.receive(dp);
			//这里对数据报发送方ip做一个校验，排除非服务器ip向本地端口发送数据，但这并不能防止udp伪造ip
			while(!checkRemoteAddress(dp.getAddress())){
				udpSocket.receive(dp);
			}
			int bufferSize = dp.getLength();
			byte[] recvPacket = decrypt(Arrays.copyOf(buffer, bufferSize));
			byte[] recvMd5 = new byte[16];
			for (int j = 2; j < 18; j++) {
				recvMd5[j - 2] = recvPacket[j];
				recvPacket[j] = 0;
			}
			if (checkMD5(recvMd5, getMD5Bytes(recvPacket))) {
				byte status = recvPacket[20];	//记录状态,0 或 1， 0表示不在线，1表示在线
				int sessionLen = recvPacket[22];
				byte[] session = new byte[sessionLen];
				for (short i = 0, j = 23; j < sessionLen + 23; i++, j++) {
					session[i] = recvPacket[j];
					recvPacket[j] = 0;
				}
				int messageIndex = -1;
				for (int j = sessionLen + 23; j < recvPacket.length; j++) {
					if (recvPacket[j] == 11) {
						messageIndex = j;
						break;
					}
				}
				int messageLen = recvPacket[messageIndex + 1] & 0xff;
				byte[] message = new byte[messageLen];
				message = Arrays.copyOfRange(recvPacket, messageIndex + 2, messageIndex + 2 + messageLen);
				String msg = new String(message, "gbk");
				if(DISPLAY_MESSAGE.equals("true")){	//允许打印通知信息
					System.out.println("\n" + msg + "\n");
				}
				if (status == 0){
					this.status = Status.LOGIN_ERROR;	//连接认证出错
				}
				else{
					this.status = Status.ONLINE;	//连接状态为在线
					return session;
				}
			} else {
				//System.out.println("连接到" + SERVICE_TYPE + "失败！尝试重新进行连接认证...");
				this.status = Status.LOGIN_MD5ERROR;	//md5校验出错
			}
		} catch (IOException e) {
			//System.out.println("连接到" + SERVICE_TYPE + "失败，服务器无响应，请稍后再试！");
			this.status = Status.LOGIN_TIMEOUT;	//连接超时
		}
		return null;
	}
	
	/**
	 * 请求下线。
	 * @param session 通过login(byte[] packet);创建得到
	 */
	private void logout(byte[] session) {
		index += 3;
		byte[] downnetPacket = generateDownnetPacket(session);
		InetAddress address = null;
		try {
			address = InetAddress.getByName(HOST_IP);
		} catch (UnknownHostException e) {
			System.out.println(e.getMessage());
			System.exit(0);
		}
		DatagramPacket datagramPacket = new DatagramPacket(downnetPacket, downnetPacket.length, address, 3848);
		try {
			udpSocket.send(datagramPacket);
			byte[] buffer = new byte[4096];
			DatagramPacket dp = new DatagramPacket(buffer, 0, buffer.length);
			udpSocket.receive(dp);
			this.status = Status.LOGOUT;	//下线
		} catch (IOException e) {
			// e.printStackTrace();
		}
	}

	/**
	 * 创建请求下线的packet
	 * @param session 通过login(byte[] packet);创建得到
	 * @return byte[] 请求下线的packet
	 */
	private byte[] generateDownnetPacket(byte[] session) {
		int packet_len = session.length + 88;
		byte[] packet = new byte[packet_len];
		byte i = -1;
		packet[++i] = 0x05;
		packet[++i] = (byte) packet_len;
		for (; i < 17;) {
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
		for (int j = 0; j < 16 - bytes.length; j++) {
			packet[++i] = 0;
		}
		packet[++i] = 0x07;
		packet[++i] = 0x08;
		String[] macs = MAC_ADDR.split(":");
		for (String str : macs) {
			packet[++i] = (byte) Integer.parseInt(str, 16);
		}
		packet[++i] = 0x14;
		packet[++i] = 0x06;
		String indexStr = String.format("%x", index);
		int indexLen = indexStr.length();
		packet[++i] = (byte) Integer.parseInt(indexStr.substring(0, indexLen - 6), 16);
		packet[++i] = (byte) Integer.parseInt(indexStr.substring(indexLen - 6, indexLen - 4), 16);
		packet[++i] = (byte) Integer.parseInt(indexStr.substring(indexLen - 4, indexLen - 2), 16);
		packet[++i] = (byte) Integer.parseInt(indexStr.substring(indexLen - 2, indexLen - 0), 16);
		for (byte b : block) {
			packet[++i] = b;
		}
		byte[] md5Bytes = getMD5Bytes(packet);
		for (int j = 0; j < md5Bytes.length; j++) {
			packet[j + 2] = md5Bytes[j];
		}
		packet = encrypt(packet);
		return packet;
	}

	/**
	 * 保持连接在线。会阻塞线程，保持连接状态status=1，当保持连接失败时，status为0或-1
	 * @param session 通过login(byte[] packet);创建得到
	 * @return 
	 * @throws InterruptedException
	 */
	private void breathe(byte[] session) throws InterruptedException {
		Thread.sleep(20000);
		int timeoutCnt = 0; // 记录超时次数
		InetAddress address = null;
		try {
			address = InetAddress.getByName(HOST_IP);
		} catch (UnknownHostException e) {
			System.out.println(e.getMessage());
			System.exit(0);
		}
		while (true) {
			byte[] breathePacket = generateBreathePacket(session);
			DatagramPacket datagramPacket = new DatagramPacket(breathePacket, breathePacket.length, address, 3848);
			try {
				udpSocket.send(datagramPacket);
				byte[] buffer = new byte[4096];
				DatagramPacket dp = new DatagramPacket(buffer, 0, buffer.length);
				udpSocket.receive(dp);
				//这里对数据报发送方ip做一个校验，排除非服务器ip向本地端口发送数据，但这并不能防止udp伪造ip
				while(!checkRemoteAddress(dp.getAddress())){
					udpSocket.receive(dp);
				}
				int bufferSize = dp.getLength();
				byte[] recvPacket = decrypt(Arrays.copyOf(buffer, bufferSize));
				byte[] recvMd5 = new byte[16];
				for (int j = 2; j < 18; j++) {
					recvMd5[j - 2] = recvPacket[j];
					recvPacket[j] = 0;
				}
				if (checkMD5(recvMd5, getMD5Bytes(recvPacket))) {
					byte status = recvPacket[20];
					if(status == 1){
						this.status = Status.ONLINE;
					}else{
						this.status = Status.BREATHE_ERROR;	//保持呼吸出错
						break;
					}
				} else {
					status = Status.BREATHE_MD5ERROR; //md5校验出错
				}
			} catch (IOException e) {
				timeoutCnt++;
				if (timeoutCnt <= 3) {
					//System.out.println("服务器失去响应: " + e.getMessage() + "。 " + "重新发送连接请求(第" + timeoutCnt + "次)...");
					continue;
				} else {
					//System.out.println("请求超时，服务器失去响应，您已断开连接！");
					this.status = Status.BREATHE_TIMEOUT; // 保持连接超时，失去响应
					break;
				}
			}
			index += 3;
			Thread.sleep(20000);
		}
	}

	/**
	 * 创建保持连接的packet
	 * @param session 通过login(byte[] packet);创建得到
	 * @return byte[] 保持连接的packet
	 */
	private byte[] generateBreathePacket(byte[] session) {
		int packet_len = session.length + 88;
		byte[] packet = new byte[packet_len];
		byte i = -1;
		packet[++i] = 0x03;
		packet[++i] = (byte) packet_len;
		for (; i < 17;) {
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
		for (int j = 0; j < 16 - bytes.length; j++) {
			packet[++i] = 0;
		}
		packet[++i] = 0x07;
		packet[++i] = 0x08;
		String[] macs = MAC_ADDR.split(":");
		for (String str : macs) {
			packet[++i] = (byte) Integer.parseInt(str, 16);
		}
		packet[++i] = 0x14;
		packet[++i] = 0x06;
		String indexStr = String.format("%x", index);
		int indexLen = indexStr.length();
		packet[++i] = (byte) Integer.parseInt(indexStr.substring(0, indexLen - 6), 16);
		packet[++i] = (byte) Integer.parseInt(indexStr.substring(indexLen - 6, indexLen - 4), 16);
		packet[++i] = (byte) Integer.parseInt(indexStr.substring(indexLen - 4, indexLen - 2), 16);
		packet[++i] = (byte) Integer.parseInt(indexStr.substring(indexLen - 2, indexLen - 0), 16);
		for (byte b : block) {
			packet[++i] = b;
		}
		byte[] md5Bytes = getMD5Bytes(packet);
		for (int j = 0; j < md5Bytes.length; j++) {
			packet[j + 2] = md5Bytes[j];
		}
		packet = encrypt(packet);
		return packet;
	}

	/**
	 * 创建连接认证的packet
	 * @return byte[] 连接认证的packet
	 */
	private byte[] generateLoginPacket() {
		int packet_len = 38 + USERNAME.length() + PASSWORD.length() + LOCAL_IP.length() + SERVICE_TYPE.length()
				+ DHCP_SETTING.length() + CLIENT_VERSION.length();
		byte[] packet = new byte[packet_len];
		byte i = -1;
		packet[++i] = 0x01;
		packet[++i] = (byte) packet_len;
		for (; i < 17;) {
			packet[++i] = 0;
		}
		packet[++i] = 0x07;
		packet[++i] = 0x08;
		String[] macs = MAC_ADDR.split(":");
		for (String str : macs) {
			packet[++i] = (byte) Integer.parseInt(str, 16);
		}
		packet[++i] = 0x01;
		packet[++i] = (byte) (USERNAME.length() + 2);
		for (byte b : USERNAME.getBytes()) {
			packet[++i] = b;
		}
		packet[++i] = 0x02;
		packet[++i] = (byte) (PASSWORD.length() + 2);
		for (byte b : PASSWORD.getBytes()) {
			packet[++i] = b;
		}
		packet[++i] = 0x09;
		packet[++i] = (byte) (LOCAL_IP.length() + 2);
		for (byte b : LOCAL_IP.getBytes()) {
			packet[++i] = b;
		}
		packet[++i] = 0x0a;
		packet[++i] = (byte) (SERVICE_TYPE.length() + 2);
		for (byte b : SERVICE_TYPE.getBytes()) {
			packet[++i] = b;
		}
		packet[++i] = 0x0e;
		packet[++i] = (byte) (DHCP_SETTING.length() + 2);
		for (char c : DHCP_SETTING.toCharArray()) {
			packet[++i] = (byte) Integer.parseInt(c + "");
		}
		packet[++i] = 0x1f;
		packet[++i] = (byte) (CLIENT_VERSION.length() + 2);
		for (byte b : CLIENT_VERSION.getBytes()) {
			packet[++i] = b;
		}
		byte[] md5Bytes = getMD5Bytes(packet);
		for (int j = 0; j < md5Bytes.length; j++) {
			packet[j + 2] = md5Bytes[j];
		}
		packet = encrypt(packet);
		return packet;
	}

	/**
	 * 搜寻服务
	 */
	private void searchService() {
		byte packet_len = 1 + 1 + 16 + 1 + 1 + 5 + 1 + 1 + 6;
		byte[] packet = new byte[packet_len];
		byte i = -1;
		packet[++i] = 0x07;
		packet[++i] = packet_len;
		for (; i < 17;) {
			packet[++i] = 0;
		}
		packet[++i] = 0x08;
		packet[++i] = 0x07;
		for (byte j = 0; j < 5; j++) {
			packet[++i] = j;
		}
		packet[++i] = 0x07;
		packet[++i] = 0x08;
		String[] macs = MAC_ADDR.split(":");
		for (String str : macs) {
			packet[++i] = (byte) Integer.parseInt(str, 16);
		}
		byte[] md5Bytes = getMD5Bytes(packet);
		for (int j = 0; j < md5Bytes.length; j++) {
			packet[j + 2] = md5Bytes[j];
		}
		packet = encrypt(packet);
		InetAddress address = null;
		try {
			address = InetAddress.getByName(HOST_IP);
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		DatagramPacket datagramPacket = new DatagramPacket(packet, packet.length, address, 3848);
		try {
			udpSocket.send(datagramPacket);
			byte[] buffer = new byte[1024];
			DatagramPacket dp = new DatagramPacket(buffer, 0, buffer.length);
			udpSocket.receive(dp);
			//这里对数据报发送方ip做一个校验，排除非服务器ip向本地端口发送数据，但这并不能防止udp伪造ip
			while(!checkRemoteAddress(dp.getAddress())){
				udpSocket.receive(dp);
			}
			int bufferSize = dp.getLength();
			byte[] recvPacket = decrypt(Arrays.copyOf(buffer, bufferSize));
			byte[] recvMd5 = new byte[16];
			for (int j = 2; j < 18; j++) {
				recvMd5[j - 2] = recvPacket[j];
				recvPacket[j] = 0;
			}
			if (checkMD5(recvMd5, getMD5Bytes(recvPacket))) {
				// 查找服务index
				short serviceIndex = -1;
				for (short j = 0; j < recvPacket.length; j++) {
					if (recvPacket[j] == 10) {
						serviceIndex = j;
						break;
					}
				}
				SERVICE_TYPE = "";
				// 取出服务内容
				if (serviceIndex != -1) {
					int serviceLen = recvPacket[serviceIndex + 1];
					for (int j = serviceIndex + 2; j < serviceIndex + serviceLen; j++) {
						SERVICE_TYPE += (char) (recvPacket[j] & 0xff);
					}
				} else {
					System.out.println("搜索服务失败！正在重试...");
					searchService();
				}
			} else {
				System.out.println("搜索服务失败！正在重试...");
				searchService();
			}
		} catch (IOException e) {
			System.out.println("搜索服务失败，服务器无响应，请稍后再试！");
			System.exit(0);
			// e.printStackTrace();
		}
	}

	/**
	 * 搜寻服务器ip地址
	 */
	private void searchServerIp() {
		byte packet_len = 1 + 1 + 16 + 1 + 1 + 5 + 1 + 1 + 16 + 1 + 1 + 6;
		byte[] packet = new byte[packet_len];
		byte i = -1;
		packet[++i] = 0x0c;
		packet[++i] = packet_len;
		for (; i < 17;) {
			packet[++i] = 0;
		}
		packet[++i] = 0x08;
		packet[++i] = 0x07;
		for (byte j = 0; j < 5; j++) {
			packet[++i] = j;
		}
		packet[++i] = 0x09;
		packet[++i] = 0x12;
		byte[] bytes = LOCAL_IP.getBytes();
		for (byte b : bytes) {
			packet[++i] = b;
		}
		for (int j = 0; j < 16 - bytes.length; j++) {
			packet[++i] = 0;
		}
		packet[++i] = 0x07;
		packet[++i] = 0x08;
		String[] macs = MAC_ADDR.split(":");
		for (String str : macs) {
			packet[++i] = (byte) Integer.parseInt(str, 16);
		}
		byte[] md5Bytes = getMD5Bytes(packet);
		for (int j = 0; j < md5Bytes.length; j++) {
			packet[j + 2] = md5Bytes[j];
		}
		packet = encrypt(packet);
		InetAddress address = null;
		try {
			address = InetAddress.getByName("1.1.1.8");
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		DatagramPacket datagramPacket = new DatagramPacket(packet, packet.length, address, 3850);
		try {
			udpSocket.send(datagramPacket);
			byte[] buffer = new byte[1024];
			DatagramPacket dp = new DatagramPacket(buffer, 0, buffer.length);
			udpSocket.receive(dp);
			//这里对数据报发送方ip做一个校验，排除非服务器ip向本地端口发送数据，但这并不能防止udp伪造ip
			while(true){
				if(dp.getAddress().getHostName().equals("1.1.1.8")){
					break;
				}
				udpSocket.receive(dp);
			}
			int bufferSize = dp.getLength();
			byte[] recvPacket = decrypt(Arrays.copyOf(buffer, bufferSize));
			// print(recvPacket);
			byte[] recvMd5 = new byte[16];
			for (int j = 2; j < 18; j++) {
				recvMd5[j - 2] = recvPacket[j];
				recvPacket[j] = 0;
			}
			if (checkMD5(recvMd5, getMD5Bytes(recvPacket))) {
				// 查找服务器地址的index
				short serverIndex = -1;
				for (short j = 0; j < recvPacket.length; j++) {
					if (recvPacket[j] == 0x0c) {
						serverIndex = j;
						break;
					}
				}
				HOST_IP = "";
				// 取出服务器ip地址
				if (serverIndex != -1) {
					int serverLen = recvPacket[serverIndex + 1];
					for (int j = serverIndex + 2; j < serverIndex + serverLen; j++) {
						HOST_IP += (recvPacket[j] & 0xff) + ".";
					}
					HOST_IP = HOST_IP.substring(0, HOST_IP.length() - 1);
				} else {
					System.out.println("搜索认证服务器失败！正在重试...");
					searchServerIp();
				}
			} else {
				System.out.println("搜索认证服务器失败！正在重试...");
				searchServerIp();
			}
		} catch (IOException e) {
			System.out.println("搜索认证服务器失败，服务器无响应，请稍后再试！");
			System.exit(0);
			// e.printStackTrace();
		}
	}

	/**
	 * MD5校验，比较两个MD5数据报是否一致
	 * @param arg0 第一个MD5数据报 16字节
	 * @param arg1 第二个MD5数据报 16字节
	 * @return 一致返回true，不一致返回false
	 */
	private boolean checkMD5(byte[] arg0, byte[] arg1) {
		boolean flag = true;
		for (int i = 0; i < arg0.length; i++) {
			if (arg0[i] != arg1[i]) {
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
	private boolean checkNetwork() {
		try {
			Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
			while (en.hasMoreElements()) {
				NetworkInterface ni = en.nextElement();
				byte[] bytes = ni.getHardwareAddress();
				String displayName = ni.getDisplayName();
				if (displayName.contains("Virtual") || displayName.contains("virtual"))
					continue;
				if (ni.isUp() && ni != null && bytes != null && bytes.length == 6) {
					List<InterfaceAddress> list = ni.getInterfaceAddresses();
					if (!list.isEmpty()) {
						return true;
					}
					//System.out.println(list.get(0).getAddress().getHostAddress().toString());
				}
			}
		} catch (SocketException e) {
			return false;
		}
		return false;
	}

	/**
	 * 校验发送方ip是否为服务器ip
	 * @param ia
	 * @return
	 */
	private boolean checkRemoteAddress(InetAddress ia){
		String ip = ia.getHostName();
		if(ip.equals(HOST_IP))
			return true;
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
				if (displayName.contains("Wireless") || displayName.contains("wireless")
						|| displayName.contains("Virtual") || displayName.contains("virtual"))
					continue;
				// System.out.println(displayName);
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
				// System.out.println(MAC_ADDR);
				List<InterfaceAddress> list = ni.getInterfaceAddresses();
				Iterator<InterfaceAddress> it = list.iterator();
				while (it.hasNext()) {
					InterfaceAddress ia = it.next();
					String ip = ia.getAddress().getHostName();
					if (ip.length() < 16) {
						LOCAL_IP = ip;
						//System.out.println(ip);
					}
				}
			}
		}
	}

	/**
	 * 用于测试打印packet字节数组，分别以10进制、16进制形式进行输出
	 * @param packet
	 */
	public static void print(byte[] packet) {
		System.out.print('[');
		for (int i = 0; i < packet.length; i++) {
			if (i < packet.length - 1)
				System.out.print((int) packet[i] + ", ");
			else
				System.out.print((int) packet[i]);
		}
		System.out.println(']');
		System.out.print('[');
		for (int i = 0; i < packet.length; i++) {
			if (i < packet.length - 1)
				System.out.print(Integer.toHexString(packet[i] & 0xff) + ", ");
			else
				System.out.print(Integer.toHexString(packet[i] & 0xff));
		}
		System.out.println(']');
	}


	/**
	 * 对byte数组直接进行摘要计算，返回加密后的byte数组
	 * @param byteArray 需要进行MD5运算的原始字节数组
	 * @return MD5摘要计算后的字节数组
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
	 * packet加密
	 * @param packet 未加密packet字节数组
	 * @return 加密后的packet字节数组
	 */
	private byte[] encrypt(byte[] packet) {
		byte[] encrypt_packet = new byte[packet.length];
		int i = 0;
		for (byte b : packet) {
			encrypt_packet[i++] = (byte) ((b & 0x80) >> 6 | (b & 0x40) >> 4 | (b & 0x20) >> 2 | (b & 0x10) << 2
					| (b & 0x08) << 2 | (b & 0x04) << 2 | (b & 0x02) >> 1 | (b & 0x01) << 7);
		}
		return encrypt_packet;
	}

	/**
	 * packet解密
	 * @param packet 加密后的packet字节数组
	 * @return 解密后的packet字节数组
	 */
	private byte[] decrypt(byte[] packet) {
		byte[] decrypt_packet = new byte[packet.length];
		int i = 0;
		for (byte b : packet) {
			decrypt_packet[i++] = (byte) ((b & 0x80) >> 7 | (b & 0x40) >> 2 | (b & 0x20) >> 2 | (b & 0x10) >> 2
					| (b & 0x08) << 2 | (b & 0x04) << 4 | (b & 0x02) << 6 | (b & 0x01) << 1);
		}
		return decrypt_packet;
	}

	/**
	 * 判断字符串是否为空、null或者空白
	 * @param str
	 * @return
	 * null、""、"  "  -- 返回true；其他返回false
	 */
	public static boolean isNullOrBlank(String str) {
		if (str == null || "".equals(str.trim()) || str.isEmpty())
			return true;
		return false;
	}
}
