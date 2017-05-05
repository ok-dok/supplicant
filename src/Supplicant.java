
import java.io.IOException;

import java.net.DatagramPacket;

import java.net.DatagramSocket;

import java.net.InetAddress;

import java.net.InterfaceAddress;

import java.net.NetworkInterface;

import java.net.SocketException;

import java.net.UnknownHostException;

import java.security.MessageDigest;

import java.util.Arrays;

import java.util.Enumeration;

import java.util.Iterator;

import java.util.List;

public class Supplicant {

    //用户名
    private static String USERNAME = "";
    //密码
    private static String PASSWORD = "";
    //认证服务器IP
    private static String HOST_IP = "";
    //物理网卡地址
    private static String MAC_ADDR = "";
    //本地IP地址
    private static String LOCAL_IP = "";
    //服务种类
    private static String SERVICE_TYPE = "internet";
    //DHCP配置，默认为0
    private static String DHCP_SETTING = "0";
    //客户端版本号
    private static String CLIENT_VERSION = "3.8.2";

    private static int connectCnt = 0; // 统计连接成功次数

    //协议里规定的
    private static int index = 0x01000000;
    private static byte[] block = {0x2a, 0x06, 0, 0, 0, 0, 0x2b, 0x06, 0, 0, 0, 0, 0x2c, 0x06, 0, 0, 0, 0, 0x2d, 0x06,
            0, 0, 0, 0, 0x2e, 0x06, 0, 0, 0, 0, 0x2f, 0x06, 0, 0, 0, 0};

    private DatagramSocket udpSocket;

    public static void main(String args[]) {
        Supplicant supplicant = new Supplicant();
        //已经获取配置文件路径的flag
        boolean flag = true;
        try {
            supplicant.loadData(args);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            flag = false;
        }
        if (flag) {
            int retryCnt = 0; // 统计尝试重连次数
            while (true) {
                // -2:连接超时，出错； -1:未上线；0:掉线; 1:在线
                int status = supplicant.run();
                if (status == -1) {
                    // 5次重连机会
                    if (++retryCnt <= 5) {
                        System.out.println("连接到 " + SERVICE_TYPE + " 失败。 尝试重新连接(第"
                                + retryCnt + "次)...");
                    } else {
                        System.out.println("重新连接失败 " + (retryCnt - 1) + " 次, 请稍后再试。");
                        break;
                    }
                } else if (status == 0) {
                    System.out.println("\n保持连接失败。 尝试重新连接...");
                } else {
                    break;
                }
            }
            supplicant.closeUdpSocket();
        }
    }

    public int run() {
        int status = -1; // -2:连接超时，出错； -1:未上线；0:掉线; 1:在线
        index = 0x01000000;
        byte[] packet = generateUpnetPacket();
        byte[] session = connect(packet);
        if (session != null) {
            status = 1; // 上线
            connectCnt++; // 统计连接次数
            try {
                status = breathe(session); // 返回0 或 -2
                if (status == 0) { // 保持在线失败，请求下线
                    disConnect(session);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        return status;
    }

    private void loadData(String[] args) throws Exception {
        //从参数中获取用户名和密码
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-u")) {
                USERNAME = args[i + 1].trim();
                if (isNullOrBlank(USERNAME)) {
                    throw new Exception("请在关键字 -u 后面输入用户名。");
                }
            }
            if (args[i].equals("-p")) {
                PASSWORD = args[i + 1].trim();
                if (isNullOrBlank(PASSWORD)) {
                    throw new Exception("请在关键字 -p 后面输入密码。");
                }
            }
        }
        if (isNullOrBlank(USERNAME) || isNullOrBlank(PASSWORD)) {
            throw new Exception("用户名和密码都不能为空。");
        }
        //获取物理地址和IP地址
        try {
            autoGetMacIp();
        } catch (SocketException e) {
            throw new Exception("获取物理地址和IP地址失败。\n"
                    + "请重新运行程序或者手动修改config.properties里的mac_addr和local_ip。 "
            );
        }
        if (isNullOrBlank(LOCAL_IP) || isNullOrBlank(MAC_ADDR)) {
            throw new Exception("获取物理地址和IP地址失败。\n"
                    + "请重新运行程序或者手动修改config.properties里的mac_addr和local_ip。 "
            );
        }
        if (!checkNetwork()) {
            throw new Exception(
                    "网卡不可用，请检查网卡是否被禁用?");
        }
        //初始化
        initUdpSocket();
        //获取认证服务器的IP
        searchServerIp();
        //获取认证服务类型
        searchService();
        //打印到控制台
        System.out.println("Service :\t" + SERVICE_TYPE);
        System.out.println("Server IP:\t" + HOST_IP);
        System.out.println("Local IP:\t" + LOCAL_IP);
        System.out.println("Mac Addr:\t" + MAC_ADDR);
        System.out.println("Username:\t" + USERNAME);
        // System.out.println("Password:\t" + PASSWORD);
    }

    /**
     *
     * 创建udp套接字
     *
     */
    private void initUdpSocket() {
        if (udpSocket == null) {
            try {
                udpSocket = new DatagramSocket(3848);
                //启用 SO_REUSEADDR 套接字选项。
                udpSocket.setReuseAddress(true);
                udpSocket.setSoTimeout(5000);
            } catch (SocketException e) {
                System.out.println(
                        "绑定本机3848端口失败。\n" + "请检查是否有另一个蝴蝶正在运行?");
                System.exit(0);
            }
        }
    }

    private void closeUdpSocket() {
        if (udpSocket != null && !udpSocket.isClosed()) {
            udpSocket.close();
        }
    }

    private void disConnect(byte[] session) {
        index += 3;
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
            byte[] buffer = new byte[4096];
            DatagramPacket dp = new DatagramPacket(buffer, 0, buffer.length);
            udpSocket.receive(dp);
            //这里不需要解析接受到的数据
        } catch (IOException e) {
            // e.printStackTrace();
        }
    }

    /**
     *
     * 创建请求下线的packet
     *
     * @param session
     *
     * @return
     *
     */
    private byte[] generateDownnetPacket(byte[] session) {
        int packet_len = session.length + 88;
        byte[] packet = new byte[packet_len];
        byte i = -1;
        packet[++i] = 0x05;
        packet[++i] = (byte) packet_len;
        for (; i < 17; ) {
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
     *
     * 保持在线
     *
     * @param session
     *
     * @return
     *
     * @throws InterruptedException
     *
     */
    private int breathe(byte[] session) throws InterruptedException {
        Thread.sleep(1000);
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
                int bufferSize = dp.getLength();
                byte[] recvPacket = decrypt(Arrays.copyOf(buffer, bufferSize));
                byte[] recvMd5 = new byte[16];
                for (int j = 2; j < 18; j++) {
                    recvMd5[j - 2] = recvPacket[j];
                    recvPacket[j] = 0;
                }
                if (checkMD5(recvMd5, getMD5Bytes(recvPacket))) {
                    byte status = recvPacket[20];
                    if (status == 0)
                        return 0; // 掉线
                } else {
                    return 0; // 掉线
                }
            } catch (IOException e) {
                timeoutCnt++;
                if (timeoutCnt < 4) {
                    System.out.println("连接到 " + SERVICE_TYPE + "失败: " + e.getMessage() + ". "
                            + "尝试重新连接(" + timeoutCnt + ")...");
                    continue;
                } else {
                    System.out.println(
                            "尝试重新连接 " + (timeoutCnt - 1) + " 失败， 请稍后再试。");
                    return -2; // 连接超时、出错，下线
                }
            }
            index += 3;
            Thread.sleep(20000);
        }
    }

    /**
     *
     * 创建保持在线的packet
     *
     * @param session
     *
     * @return
     *
     */
    private byte[] generateBreathePacket(byte[] session) {
        int packet_len = session.length + 18+70;
        byte[] packet = new byte[packet_len];
        byte i = -1;
        packet[++i] = 0x03;
        packet[++i] = (byte) packet_len;
        for (; i < 17; ) {
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
        //实际ip小于16b,后面补充0
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
     *
     * 进行连接认证
     *
     * @param packet
     *
     * @return
     *
     */
    private byte[] connect(byte[] packet) {
        InetAddress address = null;
        try {
            address = InetAddress.getByName(HOST_IP);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        DatagramPacket datagramPacket = new DatagramPacket(packet, packet.length, address, 3848);
        try {
            udpSocket.send(datagramPacket);
            byte[] buffer = new byte[4096];
            DatagramPacket dp = new DatagramPacket(buffer, 0, buffer.length);
            udpSocket.receive(dp);
            int bufferSize = dp.getLength();
            byte[] recvPacket = decrypt(Arrays.copyOf(buffer, bufferSize));
            byte[] recvMd5 = new byte[16];
            for (int j = 2; j < 18; j++) {
                recvMd5[j - 2] = recvPacket[j];
                recvPacket[j] = 0;
            }
            if (checkMD5(recvMd5, getMD5Bytes(recvPacket))) {
                //获取SUCCESS赋予status
                byte status = recvPacket[20];
                //获取SESSION赋予session
                int sessionLen = recvPacket[22];
                byte[] session = new byte[sessionLen];
                for (short i = 0, j = 23; j < sessionLen + 23; i++, j++) {
                    session[i] = recvPacket[j];
                    recvPacket[j] = 0;
                }
                //当被限速时，SESSION与MESSAGE之间有UNKNOWN05与UNKNIWN06两个字段
                //获取MESSAGE的key的index
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
                //打印从服务器返回的MESSAGE
                System.out.println(msg);
                //登陆失败返回null
                if (status == 0)
                    return null;
                else
                    return session;
            } else {
                System.out.println("连接到" + SERVICE_TYPE + "失败。 尝试重新连接...");
                return connect(packet);
            }
        } catch (IOException e) {
            System.out.println("连接到" + SERVICE_TYPE + "失败: " + e.getMessage() + "。");
        }
        return null;
    }

    /**
     *
     * 创建连接网络packet
     *
     */
    private byte[] generateUpnetPacket() {
        int packet_len = 1 + 1 + 16 + 1 + 1 + 6
                + 1 + 1 + USERNAME.length()
                + 1 + 1 + PASSWORD.length()
                + 1 + 1 + LOCAL_IP.length()
                + 1 + 1 + SERVICE_TYPE.length()
                + 1 + 1 + DHCP_SETTING.length()
                + 1 + 1 + CLIENT_VERSION.length();
        byte[] packet = new byte[packet_len];
        byte i = -1;
        packet[++i] = 0x01;
        packet[++i] = (byte) packet_len;
        for (; i < 17; ) {
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
     *
     * 搜寻服务器ip地址
     *
     */
    private void searchServerIp() {
		/*
		* 在这种结构中，裸机（非加密）数据包是：
			1字节ACTION表示数据包做什么
			1字节表示整个数据包的长度
			16字节MD5哈希
			1字节第一个字段的key
			1字节第一个字段的length（包括key和length本身）
			n字节第一个字段的data
			1字节第二个字段的key
			1字节第二个字段的length（包括key和length自身）
			n字节第二个字段的data
			......
			请注意，字段length比字段短2个字节。
		* */
        byte packet_len = 1 + 1 + 16 + 1 + 1 + 5 + 1 + 1 + 16 + 1 + 1 + 6;
        byte[] packet = new byte[packet_len];
        byte i = -1;
        //1字节ACTION表示数据包做什么
        packet[++i] = 0x0c;
        //1字节表示整个数据包的长度
        packet[++i] = packet_len;
        //16字节MD5哈希,先置0
        while (i < 17) {
            packet[++i] = 0;
        }
        //1字节第一个字段的key
        packet[++i] = 0x08;
        //1字节第一个字段的length
        packet[++i] = 0x07;
        //第一个字段的data
        for (byte j = 0; j < 5; j++) {
            packet[++i] = j;
        }
        //1字节第二个字段的key
        packet[++i] = 0x09;
        //1字节第二个字段的length
        packet[++i] = 0x12;
        //第二个字段的data是IP地址？
        byte[] bytes = LOCAL_IP.getBytes();
        for (byte b : bytes) {
            packet[++i] = b;
        }
        for (int j = 0; j < 16 - bytes.length; j++) {
            packet[++i] = 0;
        }
        //1字节第三个字段的key
        packet[++i] = 0x07;
        //1字节第三个字段的length
        packet[++i] = 0x08;
        //第三个字段的data是MAC地址？
        String[] macs = MAC_ADDR.split(":");
        for (String str : macs) {
            packet[++i] = (byte) Integer.parseInt(str, 16);
        }
        byte[] md5Bytes = getMD5Bytes(packet);
        //System.out.println(md5Bytes.toString());
        //填入16个字节的数据报MD5
        for (int j = 0; j < md5Bytes.length; j++) {
            packet[j + 2] = md5Bytes[j];
        }
        //加密数据报
        packet = encrypt(packet);
        InetAddress address = null;
        try {
            address = InetAddress.getByName("1.1.1.8");
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        //构造数据报包
        DatagramPacket datagramPacket = new DatagramPacket(packet, packet.length, address, 3850);
        try {
            udpSocket.send(datagramPacket);
            byte[] buffer = new byte[1024];
            DatagramPacket dp = new DatagramPacket(buffer, 0, buffer.length);
            udpSocket.receive(dp);
            int bufferSize = dp.getLength();
            //解密
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
                    System.out.println("搜索认证服务器失败， 正在重试...");
                    searchServerIp();
                }
            } else {
                System.out.println("搜索认证服务器失败， 正在重试...");
                searchServerIp();
            }
        } catch (SocketException e1) {
            System.out.println("搜索认证服务器IP失败，服务器没有响应！");
            System.exit(0);
            // e1.printStackTrace();
        } catch (IOException e) {
            System.out.println("搜索认证服务器IP失败，服务器没有响应！");
            System.exit(0);
            // e.printStackTrace();
        }
    }

    /**
     *
     * md5校验
     *
     * @param arg0
     *
     * @param arg1
     *
     * @return
     *
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
     *
     * 查找Internet服务
     *
     */
    private void searchService() {
        byte packet_len = 1 + 1 + 16 + 1 + 1 + 5 + 1 + 1 + 6;
        byte[] packet = new byte[packet_len];
        byte i = -1;
        packet[++i] = 0x07;
        packet[++i] = packet_len;
        for (; i < 17; ) {
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
                    System.out.println("搜索服务失败， 正在重试...");
                    searchService();
                }
            } else {
                System.out.println("搜索服务失败， 正在重试...");
                searchService();
            }
        } catch (SocketException e1) {
            System.out.println("搜索服务失败，服务器没有响应！");
            System.exit(0);
            // e1.printStackTrace();
        } catch (IOException e) {
            System.out.println("搜索服务失败，服务器没有响应！");
            System.exit(0);
            // e.printStackTrace();
        }
    }

    /**
     * 检查网卡是否可用
     *
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
                    System.out.println(list.get(0).getAddress().getHostAddress().toString());
                }
            }
        } catch (SocketException e) {
            return false;
        }
        return false;
    }

    /**
     *
     * 自动获取mac、ip地址
     *
     * @throws SocketException
     *
     */
    private void autoGetMacIp() throws SocketException {
        //获取绑定此机器的所有网络接口
        Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
        while (en.hasMoreElements()) {
            NetworkInterface ni = en.nextElement();
            //如果存在硬件地址并可以使用给定的当前权限访问，则返回该硬件地址（通常是 MAC）。
            byte[] bytes = ni.getHardwareAddress();
            //如果此网络接口已经开启并运行
            if (ni.isUp() && ni != null && bytes != null && bytes.length == 6) {
                //获取此网络接口的显示名称
                String displayName = ni.getDisplayName();
				/*System.out.println(displayName);
				输出：Realtek PCIe GBE Family Controller*/

                //排除无线和虚拟的网络
                if (displayName.contains("Wireless") || displayName.contains("wireless")
                        || displayName.contains("Virtual") || displayName.contains("virtual"))
                    continue;

                StringBuffer sb = new StringBuffer();
                for (byte b : bytes) {
					/*
					测试mac：C4:54:44:97:D0:12

					System.out.println(b);
					输出：-60，84，68，-105，-48，18

					System.out.println(Integer.toHexString(b));
					输出：ffffffc4,54,44,ffffff97,ffffffd0,12

					当负数二进制直接转换十六进制会出现以上情况，需位运算消除负数的副作用
					*/

                    // 与11110000作按位与运算以便读取当前字节高4位
                    sb.append(Integer.toHexString((b & 240) >> 4));
                    // 与00001111作按位与运算以便读取当前字节低4位
                    sb.append(Integer.toHexString(b & 15));
                    sb.append(":");
                }
                sb.deleteCharAt(sb.length() - 1);

                MAC_ADDR = sb.toString().toUpperCase();

                //获取此网络接口的全部或部分 InterfaceAddresses 所组成的列表，。
                List<InterfaceAddress> list = ni.getInterfaceAddresses();
                Iterator<InterfaceAddress> it = list.iterator();
                while (it.hasNext()) {
                    InterfaceAddress ia = it.next();
					/*
					System.out.println(ia.getAddress().toString());
					输出：/172.16.172.24
							/fe80:0:0:0:c4f:9e87:d856:9872%eth1
					*/
                    String ip = ia.getAddress().toString().split("/")[1];
                    if (ip.length() < 16) {
                        LOCAL_IP = ip;
                        // System.out.println(ip);
                    }
                }
            }
        }
    }

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
                System.out.print(Integer.toHexString(packet[i]) + ", ");
            else
                System.out.print(Integer.toHexString(packet[i]));
        }
        System.out.println(']');
    }

    /**
     *
     * 对byte数组进行MD5摘要计算，返回加密后的16进制字符串
     *
     *
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
     *
     * 对byte数组直接进行摘要计算，返回加密后的byte数组
     *
     * @param byteArray
     *
     * @return
     *
     */
    private byte[] getMD5Bytes(byte[] byteArray) {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (Exception e) {
            System.out.println("获取数据报的MD5信息摘要失败。");
            e.printStackTrace();
            return null;
        }
        byte[] md5Bytes = md5.digest(byteArray);
        return md5Bytes;
    }

    /**
     *
     * 加密
     *
     * @param packet
     *
     * @return
     *
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
     *
     * 解密
     *
     * @param packet
     *
     * @return
     *
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

    public static boolean isNullOrBlank(String str) {
        if (str == null || "".equals(str.trim()) || str.isEmpty())
            return true;
        return false;
    }
}
