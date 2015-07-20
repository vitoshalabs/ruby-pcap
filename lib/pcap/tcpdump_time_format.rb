module Pcap
  module TcpdumpTimeFormat
    # tcpdump style format
    def tcpdump
      sprintf "%0.2d:%0.2d:%0.2d.%0.6d", hour, min, sec, tv_usec
    end
  end
end

Time.include Pcap::TcpdumpTimeFormat
