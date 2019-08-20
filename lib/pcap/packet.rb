module Pcap
  class Packet
    def to_s
      'Some packet'
    end

    def inspect
      "#<#{self.class}: #{self}>"
    end
  end

  class IPPacket
    def to_s
      "#{ip_src} > #{ip_dst}"
    end
  end

  class IPv6Packet
    def to_s
      "#{src_s} > #{dst_s} next header #{ip_nh}"
    end
  end

  class TCPPacket
    def tcp_data_len
      ip_len - 4 * (ip_hlen + tcp_hlen)
    end

    def tcp_flags_s
      return \
	(tcp_urg? ? 'U' : '.') +
	(tcp_ack? ? 'A' : '.') +
	(tcp_psh? ? 'P' : '.') +
	(tcp_rst? ? 'R' : '.') +
	(tcp_syn? ? 'S' : '.') +
        (tcp_fin? ? 'F' : '.')
    end

    def to_s
      "#{src}:#{sport} > #{dst}:#{dport} #{tcp_flags_s}"
    end

    def src_mac_address
      return unpack_hex_string(raw_data[6, 12])
    end

    def dst_mac_address
      return unpack_hex_string(raw_data[0, 6])
    end

    def unpack_hex_string(hex)
      return hex.unpack('H2H2H2H2H2H2').join('')
    end
  end

  class UDPPacket
    def to_s
      "#{src}:#{sport} > #{dst}:#{dport} len #{udp_len} sum #{udp_sum}"
    end
  end

  class ICMPPacket
    def to_s
      "#{src} > #{dst}: icmp: #{icmp_typestr}"
    end
  end

  class TCPv6Packet

    def tcp_flags_s
      return \
  (tcp_urg? ? 'U' : '.') +
  (tcp_ack? ? 'A' : '.') +
  (tcp_psh? ? 'P' : '.') +
  (tcp_rst? ? 'R' : '.') +
  (tcp_syn? ? 'S' : '.') +
        (tcp_fin? ? 'F' : '.')
    end
    
    def to_s
      "#{src_s}:#{sport} > #{dst_s}:#{dport} #{tcp_flags_s}"
    end
  end

  class UDPv6Packet
    def to_s
      "#{src_s}:#{sport} > #{dst_s}:#{dport} len #{udp_len} sum #{udp_sum}"
    end
  end
  #
  # Backword compatibility
  #
  IpPacket = IPPacket
  IpAddress = IPAddress
  TcpPacket = TCPPacket
  UdpPacket = UDPPacket
end
