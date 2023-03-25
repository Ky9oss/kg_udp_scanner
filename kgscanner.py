import socket
import os
import struct
import ipaddress
import sys
import threading



# global
flag_end = False



# 获取当前正在使用网卡的IP地址
def extract_ip():
    st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:       
        st.connect(('10.255.255.255', 1))
        IP = st.getsockname()[0]
        print('[^_^] 当前联网的网卡的IP为：'+IP)
    except Exception:
        IP = '127.0.0.1'
    finally:
        st.close()
    return IP



# 用于解析IP头部
class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff) #<代表小端序，低位字节放在较低的内存地址上，高位字节放在较高的内存地址上。一个内存地址代表一个字节（8bit）的存储空间。

        #版本号
        self.ver = header[0] >> 4 #>>表示二进制向右移动四位
        #IP头长度(有多少个16进制字符)
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
        protocol_map = {1: 'ICMP'}
        try:
            self.protocol = protocol_map[self.ptc_num]#注意这种利用字典映射的方式
        except Exception as e:
            print(f'[ToT] {e}\n目前尚不支持协议序号为{self.ptc_num}的数据')


class ICMP:
    def __init__(self, buff=None) -> None:
        # 这里仅为前三个必须存在的字段
        header = struct.unpack('<BBH', buff)
        # ICMP的类型
        self.type = header[0]
        # ICMP的code
        self.code = header[1]
        self.checksum = header[2]
        # 前三个数据任何ICMP都有，后面的不一定有，不同ICMP包不同,且头的长度有可能不一致





def main(HOSTS):
    MESSAGE = 'KGPYTHON'
    MYHOST = extract_ip()


    # 准备工作
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    #接包时包含IP头
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sniffer.bind((MYHOST, 0))

    def udpScan(socket_udp):
        try:
            hosts = ipaddress.ip_network(HOSTS).hosts()
        except ValueError:
            print('-----------------------------------------------')
            print("您的子网地址中有一个或多个主机位设置没有被正确移除\n例如166.166.1.166/24，应该改为166.166.1.0/24。\n请使用Ctrl+C退出程序后重新尝试")
            print('-----------------------------------------------')
            sys.exit()
        for host in hosts:
            socket_udp.sendto(bytes(MESSAGE, 'utf-8'), (str(host), 65121))

        global flag_end
        flag_end = True


    socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    threading.Thread(target=udpScan,args=(socket_udp,)).start()
    try:
        while True:
            data = sniffer.recvfrom(65535)[0]
            ip = IP(data[0:20])
            offset = ip.ihl*4 #注意，头长度要乘以4。因为ihl只占4位比特，所以最大表示15个字节（1111），但IP头长度最大为60字节，所以等同于ihl表示有多少个十六进制数  
            icmp = ICMP(data[offset:offset+4])
            #utf-8中，一个字符一个字节，一个汉字通常是三字节，比较偏的汉字是四字节
            if data[-8:] == bytes(MESSAGE,'utf-8') :
                if icmp.code == 3 and icmp.type == 3:
                    print(f'{ip.src_ip} is up!')

    except KeyboardInterrupt:
        print("GoodBye!")
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    




if __name__ == '__main__':
    if len(sys.argv[1:]) == 1:
        HOSTS = str(sys.argv[1])
        main(HOSTS)
    else:
        print('Input the subnet you want to scan')
        sys.exit()
    
