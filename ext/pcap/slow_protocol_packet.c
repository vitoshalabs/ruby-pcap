#include "ruby_pcap.h"

VALUE cSPPacket;
VALUE cLACPPacket;

VALUE
setup_slow_protocol_packet(pkt, nl_len)
  struct packet_object *pkt;
  int nl_len;
{
  VALUE class;

  DEBUG_PRINT("setup_slow_protocol_packet");
  if (pkt->data[14] == 0x01) {
    class = cLACPPacket;
  } else {
    class = cSPPacket;
  }
  return class;
}

void
Init_sp_packet(void)
{
    DEBUG_PRINT("Init_sp_packet");

    cSPPacket = rb_define_class_under(mPcap, "SPPacket", cPacket);
    cLACPPacket = rb_define_class_under(mPcap, "LACPPacket", cSPPacket);
}
