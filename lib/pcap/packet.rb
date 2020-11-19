module Pcap
  class Packet
    def to_s
      'Some packet'
    end

    def inspect
      "#<#{self.class}: #{self}>"
    end
    def src_mac_address
      return unpack_hex_string(raw_data[6, 12])
    end

    def dst_mac_address
      return unpack_hex_string(raw_data[0, 6])
    end

    def ethertype
      raw_data[12, 14].unpack('n')[0]
    end

    def unpack_hex_string(hex)
      hex.unpack('H2H2H2H2H2H2').join('')
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

  # Slow protocol frames
  class SPPacket

    # return Slow protocol subtype: 0x01 LACP, 0x02 Marker 0x03 EFM OAM
    def sp_subtype
      raw_data[14].unpack('C')[0]
    end
  end

  # LACP frames
  class LACPPacket

    LACP_ACTIVITY = 0x01
    LACP_TIMEOUT = 0x02
    LACP_AGGR = 0x04
    LACP_SYNC = 0x08
    LACP_COLLECTING = 0x10
    LACP_DISTR = 0x20
    LACP_DEFAULTED = 0x40
    LACP_EXPIRED = 0x80

    # return LACP Version
    def version
      raw_data[15].unpack('C')[0]
    end

    # return Actor LACP flags in human readable form
    def actor_flags
      parse_flags(actor_info['Actor State'])
    end

    # return Actor LACP flags in human readable form
    def partner_flags
      parse_flags(partner_info['Partner State'])
    end

    # return LACP Actor TLV
    def actor_info
      # throw error if 1st TLV is not Actor
      raise 'error in actor TLV' if raw_data[16].unpack('C')[0] != 1
      {
        'Actor System Priority' => raw_data[18,19].unpack('n')[0],
        'Actor System Id' => unpack_hex_string(raw_data[20, 26]),
        'Actor Key' => raw_data[26,27].unpack('n')[0],
        'Actor Port Priority' => raw_data[28,29].unpack('n')[0],
        'Actor Port' => raw_data[30,31].unpack('n')[0],
        'Actor State' => raw_data[32].unpack('C')[0].to_i
      }
    end
    # return LACP Partner TLV
    def partner_info
      # throw error if 2nd TLV is not Partner
      actor_tlv_len = raw_data[17].unpack('C')[0]
      base = 16 + actor_tlv_len
      raise 'error in partner TLV' if raw_data[base].unpack('C')[0] != 2
      base += 2
      {
        'Partner System Priority' => raw_data[base, base + 1].unpack('n')[0],
        'Partner System Id' => unpack_hex_string(raw_data[base + 2, base + 7]),
        'Partner Key' => raw_data[base + 8,base + 9].unpack('n')[0],
        'Partner Port Priority' => raw_data[base + 10,base + 11].unpack('n')[0],
        'Partner Port' => raw_data[base + 12,base + 13].unpack('n')[0],
        'Partner State' => raw_data[base + 14].unpack('C')[0].to_i
      }
    end

    # parse LACP flags based on 802.3ad-2000
    def parse_flags(flags)
      {
        'Activity' => (LACP_ACTIVITY & flags).zero? ? 'Passive' : 'Active',
        'Timeout' => (LACP_TIMEOUT & flags).zero? ? 'Long' : 'Short',
        'Aggregation' => (LACP_AGGR & flags).zero? ? 'Individual' : 'Aggregatable',
        'Synchronization' => (LACP_SYNC & flags).zero? ? 'OutSync' : 'InSync',
        'Collecting' => (LACP_COLLECTING & flags).zero? ? 'NotCollecting' : 'Collecting',
        'Distributing' => (LACP_DISTR & flags).zero? ? 'NotDistributing' : 'Distributing',
        'Defaulted' => (LACP_DEFAULTED & flags).zero? ? 'RecvPartner' : 'DefaultPartner',
        'Expired' => (LACP_EXPIRED & flags).zero? ? 'NotExpired' : 'Expired'
      }
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
