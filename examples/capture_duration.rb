#!/usr/bin/ruby
# frozen_string_literal: true

require 'pcap'
require 'pcap/pcaplet'

iface = ARGV[0] || 'en0'
duration = (ARGV[1] || 10).to_i
count = 0
capture = Pcap::Capture.open_live(iface, 65_535, true)
Thread.new do
  sleep duration
  if capture.closed?
    puts 'device is already closed!'
  else
    puts 'signaling OS to stop capture!'
    capture.breakloop
  end
end
puts "starting capture on #{iface} for #{duration} seconds"
start_time = Time.now
capture.loop do |pkt|
  puts "Got #{pkt}"
  count += 1
end
capture.close
end_time = Time.now
puts "packets count #{count} completed in #{end_time - start_time} seconds"
