from scapy.all import *
import os
import socket
import struct
import select
import time
ICMP_ECHO_REQUEST = 8

def checksum(data):
    """ICMP paketinin kontrol toplamını hesaplar"""
    sum_ = 0
    count_to = (len(data) // 2) * 2
    count = 0
    while count < count_to:
        this_val = data[count + 1] * 256 + data[count]
        sum_ = sum_ + this_val
        sum_ = sum_ & 0xffffffff
        count = count + 2

    if count_to < len(data):
        sum_ = sum_ + data[len(data) - 1]
        sum_ = sum_ & 0xffffffff

    sum_ = (sum_ >> 16) + (sum_ & 0xffff)
    sum_ = sum_ + (sum_ >> 16)
    answer = ~sum_
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def create_packet():
    """ICMP paketi oluşturur"""
    # 0 ile doldurulmuş 16 baytlık bir ICMP paketi oluştur
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, os.getpid(), 1)
    data = b"hello"
    checksum_val = checksum(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(checksum_val), os.getpid(), 1)
    return header + data


def parse_packet(packet):
    """Gelen ICMP paketini işler"""
    icmp_header = packet[20:28]
    type_, code, checksum, packet_id, sequence = struct.unpack("bbHHh", icmp_header)
    return type_, code, checksum, packet_id, sequence


def ping(dest_addr, timeout=2, count=4):
    """Ping işlemini gerçekleştirir"""
    try:
        dest_ip = socket.gethostbyname(dest_addr)
    except socket.gaierror:
        print("Invalid address")
        return

    for i in range(count):
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        packet = create_packet()

        icmp_socket.sendto(packet, (dest_ip, 0))

        start_time = time.time()
        ready = select.select([icmp_socket], [], [], timeout)
        if ready[0]:
            recv_packet, addr = icmp_socket.recvfrom(1024)
            elapsed_time = (time.time() - start_time) * 1000
            type_, code, checksum, packet_id, sequence = parse_packet(recv_packet)
            if type_ == 0 and code == 0:
                print(f"{len(recv_packet)} bytes from {addr[0]}: icmp_seq={sequence} time={elapsed_time:.2f} ms")
            else:
                print("Error: Packet received with ICMP type", type_, "and code", code)
        else:
            print("Request timed out.")
        icmp_socket.close()
        time.sleep(1)  # Bir sonraki ping isteği için bekle






def send_unreachable_packet(dest_addr):
    """Destination Unreachable ICMP paketi gönderir"""
    try:
        dest_ip = socket.gethostbyname(dest_addr)
    except socket.gaierror:
        print("Invalid address")
        return

    # ICMP Hedefe Ulaşılamaz mesajı oluşturmak için özel bir sınıf tanımla
    class DestinationUnreachable(ICMP):
        def mysummary(self):
            return self.sprintf("ICMP Destination Unreachable (Type: %ICMP.type%, Code: %ICMP.code%)")

    # ICMP Hedefe Ulaşılamaz mesajı oluştur
    icmp_packet = IP(dst=dest_ip)/ICMP(type=3)/DestinationUnreachable()
    send(icmp_packet)




def protocol_unreachable(dest_addr):

    """Protocol Unreachable ICMP paketi gönderir"""
    try:
            dest_ip = socket.gethostbyname(dest_addr)
    except socket.gaierror:
            print("Invalid address")
            return
    
        # ICMP Protocol Unreachable mesajı oluşturmak için özel bir sınıf tanımla
    class ProtocolUnreachable(ICMP):
        def mysummary(self):
            return self.sprintf("ICMP Protocol Unreachable (Type: %ICMP.type%, Code: %ICMP.code%)")

    # ICMP Protocol Unreachable mesajını oluştur
    icmp_packet = IP(dst=dest_ip)/ICMP(type=3, code=2)/ProtocolUnreachable()

    # Paketi gönder
    send(icmp_packet)

def redirect_for_host(dest_addr):

    """Redirect for host ICMP paketi gönderir"""
    try:
            dest_ip = socket.gethostbyname(dest_addr)
    except socket.gaierror:
            print("Invalid address")
            return
    
        # ICMP Protocol Unreachable mesajı oluşturmak için özel bir sınıf tanımla
    class ProtocolUnreachable(ICMP):
        def mysummary(self):
            return self.sprintf("ICMP Protocol Unreachable (Type: %ICMP.type%, Code: %ICMP.code%)")



    class RedirectForHost(ICMP):
        def mysummary(self):
            return self.sprintf("ICMP Redirect for Host (Type: %ICMP.type%, Code: %ICMP.code%)")

    # ICMP Redirect for Host mesajını oluştur
    icmp_packet = IP(dst=dest_ip)/ICMP(type=5, code=1)/RedirectForHost()

    # Paketi gönder
    send(icmp_packet)

def pointer_hatası(dest_addr):

    """Redirect for host ICMP paketi gönderir"""
    try:
            dest_ip = socket.gethostbyname(dest_addr)
    except socket.gaierror:
            print("Invalid address")
            return
    
        # ICMP Protocol Unreachable mesajı oluşturmak için özel bir sınıf tanımla
    class ProtocolUnreachable(ICMP):
        def mysummary(self):
            return self.sprintf("ICMP Protocol Unreachable (Type: %ICMP.type%, Code: %ICMP.code%)")


        # ICMP Parameter Problem mesajı oluşturmak için özel bir sınıf tanımla
    class ParameterProblem(ICMP):
        def mysummary(self):
            return self.sprintf("ICMP Parameter Problem (Type: %ICMP.type%, Code: %ICMP.code%)")

    # ICMP Parameter Problem mesajını oluştur
    icmp_packet = IP(dst=dest_ip)/ICMP(type=12, code=0)/ParameterProblem()

    # Paketi gönder
    send(icmp_packet)



a = ""
while a != "c":
    a = input("Yapmak istediğiniz işlemi giriniz:\n1) Ping atmak\n2) Hedefe ulaşılamadı hatası\n3) Protokole ulaşılamadı hatası\n4) Redirect for host hatası\n5) Pointer indicates the hatası\nSeçiminizi yapın (Çıkmak için 'c' girin): ")

    if a == "1":
        print("Ping işlemi başlatılıyor...")
        dest_ip = input("Ping atmak istediğiniz IP adresini girin: ")
        ping(dest_ip)
    elif a == "2":
        print("Hedefe ulaşılamadı hatası gönderiliyor...")
        dest_ip = input("Hedef IP adresini girin: ")
        send_unreachable_packet(dest_ip)
      
    elif a == "3":
        print("Protokole ulaşılamadı hatası gönderiliyor...")
        dest_ip = input("Hedef IP adresini girin: ")
        protocol_unreachable(dest_ip)
      
    elif a == "4":
        print("Redirect for host hatası gönderiliyor...")
        dest_ip = input("Hedef IP adresini girin: ")
        redirect_for_host(dest_ip)
       
    elif a == "5":
        print("Pointer indicates hatası gönderiliyor...")
        dest_ip = input("Hedef IP adresini girin: ")
        pointer_hatası(dest_ip)
       

print("Programdan çıkılıyor...")

