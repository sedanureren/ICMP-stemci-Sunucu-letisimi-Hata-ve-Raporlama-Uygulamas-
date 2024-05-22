from scapy.all import * 
from scapy.layers.inet import ICMP 

def log_error(error_message, ip_address,dest_ip, error_code):
    """Belirli bir hata türünü ve ilgili IP adresini bir dosyaya kaydeder."""
    desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    log_file_path = os.path.join(desktop_path, "error_log.txt")
    with open(log_file_path, "a") as file:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"{timestamp}: {ip_address} adresinden{dest_ip} adresine gönderilen pakette {error_message}: {error_code} hatası alındı.\n")

def packet_callback(packet):
    if packet.haslayer(ICMP):
        icmp_packet = packet.getlayer(ICMP)
        if icmp_packet.type == 8:  # ICMP Echo Request
            error_message="ICMP Echo Request Paketi Yakalandı."
            print(error_message)
            log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)
        elif icmp_packet.type == 0:  # ICMP Echo Reply
            error_message="ICMP Echo Reply Paketi Yakalandı."
            print(error_message)
            log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)
        elif icmp_packet.type == 3:  # Destination Unreachable
            print("Hedef Ulaşılamaz Paketi Yakalandı.")
            if icmp_packet.code == 0:
                error_message="Ağa ulaşılamaz Hata kodu::"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)
                
            
                

            elif icmp_packet.code == 1:
                error_message="Hosta ulaşılamaz Hata kodu::"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)


            elif icmp_packet.code == 2:

                error_message="ICMP Echo Request Paketi Yakalandı."
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)


            elif icmp_packet.code == 3:


                error_message="Port ulaşılamaz Hata kodu::"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)
            elif icmp_packet.code == 4:

                error_message="Fragmentation gerekli ve DF set Hata kodu::."
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)
            elif icmp_packet.code == 5:

                error_message="Kaynak yönlendirme hatalı Hata kodu::"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)
            elif icmp_packet.code == 6:


                error_message="hedef ağ bilinmiyor Hata kodu::"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)
            elif icmp_packet.code == 7:


                error_message="hedef host bilinmiyor Hata kodu::"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)
            elif icmp_packet.code == 8:

                error_message="kaynak host isolated Hata kodu::."
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)

            elif icmp_packet.code == 9:

                error_message="ağ yöneticisi yasaklandı Hata kodu::"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)

            elif icmp_packet.code == 10:


                error_message="host admin yasaklandı Hata kodu:."
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)

            elif icmp_packet.code == 11:

                error_message="TOS için ağa erişilemiyor Hata kodu:"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code) 

            elif icmp_packet.code == 12:
                error_message="TOS için ana makineye ulaşılamıyor Hata kodu:"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)


            elif icmp_packet.code == 13:
                error_message="Communication admin yasaklandı Hata kodu:"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)


            else:
                print("Diğer Destination Unreachable Kodu:", icmp_packet.code)
        elif icmp_packet.type == 4:  # ICMP Echo Reply
            
            print("Source Quench")
        elif icmp_packet.type == 5:  # ICMP Echo Reply
            if icmp_packet.code == 0:
                error_message="Ağ için datagramı yönlendir Hata kodu:"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)
            elif icmp_packet.code == 1:
                error_message="Host için datagramı yönlendir Hata kodu:"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)
    
            elif icmp_packet.code == 2:

                error_message="TOS & Network için datagramı yönlendir Hata kodu:"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)
            elif icmp_packet.code == 3:

                error_message="TOS & Host için datagramı yönlendir Hata kodu:"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)
        elif icmp_packet.type == 9:  # ICMP Echo Reply
            print("Router advertisement. Hata kodu::",icmp_packet.code)
        elif icmp_packet.type == 10:  # ICMP Echo Reply
            print("Router selection.Hata kodu::",icmp_packet.code)
        elif icmp_packet.type == 11:  # ICMP Echo Reply
            if icmp_packet.code == 0:

                error_message="Time To Live exceeded in transit Hata kodu:"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)
            elif icmp_packet.code == 1:
                print("Fragment reassemble time exceeded Hata kodu::",icmp_packet.code)
        elif icmp_packet.type == 12:  # ICMP Echo Reply
            if icmp_packet.code == 0:

                error_message="Pointer indicates the error(Parameter Problem) Hata kodu:"
                print(error_message)
                log_error(error_message, packet[IP].src,packet[IP].dst, icmp_packet.code)
            elif icmp_packet.code == 1:
                print("Missing a required option(Parameter Problem) Hata kodu::",icmp_packet.code)
            elif icmp_packet.code == 2:
                print("Bad lenght (Parameter Problem) Hata kodu::",icmp_packet.code)
        elif icmp_packet.type == 13:  # ICMP Echo Reply
            print("Time Stamp. Hata kodu::",icmp_packet.code)
        elif icmp_packet.type == 14:  # ICMP Echo Reply
            print("time Stamp Reply. Hata kodu::",icmp_packet.code)
        elif icmp_packet.type == 15:  # ICMP Echo Reply
            print("Information request. Hata kodu::",icmp_packet.code)
        elif icmp_packet.type == 16:  # ICMP Echo Reply
            print("ınformation reply. Hata kodu::",icmp_packet.code)
        elif icmp_packet.type == 17:  # ICMP Echo Reply
            print("address mask request. Hata kodu::",icmp_packet.code)
        elif icmp_packet.type == 18:  # ICMP Echo Reply
            print("address mask reply. Hata kodu::",icmp_packet.code)
        elif icmp_packet.type == 30:  # ICMP Echo Reply
            print("traceroute(tracert). Hata kodu::",icmp_packet.code)
        else:
            print("Diğer ICMP Paketi Türü:", icmp_packet.type)

# Paket yakalama işlemi
sniff(prn=packet_callback, filter="icmp", store=0)