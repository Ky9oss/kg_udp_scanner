import socket
import os
import struct
import ipaddress
import sys




#socket.gethostname()获取当前正在运行python解释器的主机（不好用，root下获取到了127.0.1.1）
#HOST = socket.gethostbyname(socket.gethostname())


#注意函数运行顺序：程序读到def定义时，会预先记录下函数定义的名称，但不会运行里面的内容。当需要执行函数时才读取函数的内容


def extract_ip():
    st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:       
        st.connect(('10.255.255.255', 1))
        IP = st.getsockname()[0]
        print('[^_^] 当前IP为：'+IP)
    except Exception:
        IP = '127.0.0.1'
    finally:
        st.close()
    return IP

# <<属性较多时用class的初始化比较有优势，不然用函数的话得返回一个大数组，你还要记住各属性在数组中的位置才能调用>>
class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff) #<代表小端序，低位字节放在较低的内存地址上，高位字节放在较高的内存地址上。一个内存地址代表一个字节（8bit）的存储空间。

        #版本号
        self.ver = header[0] >> 4 #>>表示二进制向右移动四位
        #IP头长度
        self.ihl = header[0] & 0xF #0xF二进制为1111，与运算之后只剩下后面四位
        #Differentiated Service Field:前六位指示该包的优先级，后两位指示堵塞状态
        self.dsf = header[1]
        #IP包总长度
        self.tol = header[2]
        #标识。如果TCP头部分片，则标识指示了哪些分片来自同一个包
        self.ide = header[3]
        #前3bit记录是否分片，后13bit记录分片后的偏移量（该片在原完整TCP头部中的位置）
        self.offset = header[4]
        self.ttl = header[5]
        #指出运输层的协议,用数字表示
        self.ptc_num = header[6]
        self.checksum = header[7]
        self.src_binary = header[8]
        self.dst_binary = header[9]

        #将二进制转化为可读的形式
        self.src_ip = ipaddress.ip_address(self.src_binary)
        self.dst_ip = ipaddress.ip_address(self.dst_binary)
        protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        try:
            self.protocol = protocol_map[self.ptc_num]#注意这种利用字典映射的方式
        except Exception as e:
            print(f'[ToT] {e}\n目前尚不支持协议序号为{self.ptc_num}的数据')






def linux_main():
    HOST = extract_ip()
    socket_protocol = socket.IPPROTO_ICMP
    # sniffer为原始套接字
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    #bind函数只能绑定自己的网卡的IP:127.0.0.1或内网IP
    sniffer.bind((HOST, 0))#因为是IP层的原始套接字，所以端口为0
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)#意思是抓包的同时也要抓IP头部（默认为不抓头部）
    try:
        while True:
            data, _ = sniffer.recvfrom(65565)
            ip_head = IP(data[0:20])
            print(f'[^_^] {ip_head.protocol} : {ip_head.src_ip} --> {ip_head.dst_ip}')
            #print("[^_^] 收到["+address[0]+"]的包")
    except KeyboardInterrupt:
        print("再见！")
        sys.exit()


def windows_main(self):
    HOST = extract_ip()
    socket_protocol = socket.IPPROTO_IP


    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))#因为是IP层的原始套接字，所以端口为0
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)#意思是抓包的同时也要抓IP头部（默认为不抓头部）
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)#如果是windows，则发送IOCTL消息，请求网卡进入混杂模式
    try:
        while True:
            data, address = sniffer.recvfrom(65565)
            ip_head = IP(data)
            print(f'[^_^] {ip_head.protocol} : {ip_head.src_ip} --> {ip_head.dst_ip}')
            #print("[^_^] 收到["+address[0]+"]的包")
    except KeyboardInterrupt:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("再见！")
        sys.exit()
    




if __name__ == '__main__':
    print("[os.name]: " + os.name)
    if os.name == 'nt':
        windows_main()
    else:
        linux_main()
