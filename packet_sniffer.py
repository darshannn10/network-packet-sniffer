import socket 
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def eth_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14]) # unpacking the ethernet frame to retrieve only the first 14 bytes
    # !-> tells to use standard size and network endianness(big endian) whne unpacking
    # 6s -> takes 6 characters to build a string for the destination address
    # 6s -> takes the sources address
    # H -> takes an unsigned short for the type
    return format_mac(dest_mac), format_mac(src_mac), socket.htons(proto), data[14:]

def format_mac(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)  
     # {:02x} -> Format ints into string of hex
    return ":".join(bytes_str).upper()

def main():
   conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
   # SOCK_RAW -> raw packet, instead of processed packet
   # socket.ntohs(3) -> tells to capture everything including ethernet frames, which includes TCP, UDP & ICMP
   
   while True:
       raw_data, addr = conn.recvfrom(65535)
       dest_mac, src_mac, eth_proto, data = eth_frame(raw_data)
       print('\nEthernet Frame:')
       print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
       #print(data)
       if eth_proto == 8:
        (version, header_length, ttl, proto, src, target, data) = ipv4_packets(data)
        print(TAB_1 + 'IPv4 Packet: ')
        print(TAB_2 + 'version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
        print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
        
        if proto == 1:
            icmp_type, code, checksum, data = icmp_packet(data)
            print(TAB_1 + 'ICMP Packet: ')
            print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
            print(TAB_2 + 'Data: ')
            print(format_multi_line(DATA_TAB_3, data))

        elif proto == 6:
            (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
            print(TAB_1 + 'TCP Segment:')
            print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
            print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
            print(TAB_2 + 'Flags:')
            print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN:{}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
            print(TAB_2 + 'Data:')
            print(format_multi_line(DATA_TAB_3, data))
        
        elif proto == 17:
            src_port, dest_port, length, data = udp_segment(data)
            print(TAB_1 + 'UDP Segment: ')
            print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length {}'.format(src_port, dest_port, length))

        else:
            print('Data: ')
            print(format_multi_line(DATA_TAB_1, data))



## Unpacking Different packets

# unpacking IPv4 packets
def ipv4_packets(data):
    version_data_length = data[0]
    version = version_data_length >> 4  #bit-shifting to right by 4 bits to move header length data out of 1 byte in the version_data_length variable
    
    header_length = (version_data_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    # ! 8x B B 2x 4s 4s -> format in which the data is going to be unpacked
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpacking ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacking TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 16) >> 4
    flag_psh = (offset_reserved_flag & 8) >> 3
    flag_rst = (offset_reserved_flag & 4) >> 2
    flag_syn = (offset_reserved_flag & 2) >> 1
    flag_fin = (offset_reserved_flag & 1)
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpacking UDP segment
def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x, H', data[:8])
    return src_port, dest_port, length, data[8:]
    
# Formatting multi-line data (Eg: doesnt show 7000 characters on same line while showing the results)
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        #converting strings  to hexadecimal bytes format
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == "__main__":
  main()