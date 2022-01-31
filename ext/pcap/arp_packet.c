/*
 *  arp_packet.c
 *
 *  $Id: arp_packet.c,v 0.1
 *
 */

#include "ruby_pcap.h"
#include <netdb.h>

struct arphdr
  {
    unsigned short int ar_hrd;  /* Format of hardware address.  */
    unsigned short int ar_pro;  /* Format of protocol address.  */
    unsigned char ar_hln;       /* Length of hardware address.  */
    unsigned char ar_pln;       /* Length of protocol address.  */
    unsigned short int ar_op;   /* ARP opcode (command).  */
    unsigned char ar_sha[6];    /* Sender hardware address.  */
    unsigned char ar_sip[4];    /* Sender IP address.  */
    unsigned char ar_tha[6];    /* Target hardware address.  */
    unsigned char ar_tip[4];    /* Target IP address.  */
  };


VALUE cARPPacket;

VALUE
setup_arp_packet(pkt, nl_len)
     struct packet_object *pkt;
     int nl_len;
{
    VALUE class;

    DEBUG_PRINT("setup_arp_packet");

    class = cARPPacket;

    return class;
}

#define ARP_HDR(pkt)    ((struct arphdr *)LAYER3_HDR(pkt))

#define ARPP_METHOD(func, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct packet_object *pkt;\
    struct arphdr *arp;\
    DEBUG_PRINT(#func);\
    GetPacket(self, pkt);\
    arp = ARP_HDR(pkt);\
    return (val);\
}

ARPP_METHOD(arpp_hw,     INT2FIX(ntohs(arp->ar_hrd)))
ARPP_METHOD(arpp_prot,   INT2FIX(ntohs(arp->ar_pro)))
ARPP_METHOD(arpp_hlen,   INT2FIX(arp->ar_hln))
ARPP_METHOD(arpp_plen,   INT2FIX(arp->ar_pln))
ARPP_METHOD(arpp_op,     INT2FIX(ntohs(arp->ar_op)))
ARPP_METHOD(arpp_s_hw,   rb_str_new(arp->ar_sha,6))
ARPP_METHOD(arpp_s_ip,   UINT32_2_NUM(ntohl( *((unsigned long int *) arp->ar_sip))))
ARPP_METHOD(arpp_t_hw,   rb_str_new(arp->ar_tha,6))
ARPP_METHOD(arpp_t_ip,   UINT32_2_NUM(ntohl( *((unsigned long int *) arp->ar_tip))))


void
Init_arp_packet(void)
{
    DEBUG_PRINT("Init_arp_packet");

    cARPPacket = rb_define_class_under(mPcap, "ARPPacket", cPacket);
    rb_define_method(cARPPacket, "hw", arpp_hw, 0);
    rb_define_method(cARPPacket, "protocol", arpp_prot, 0);
    rb_define_method(cARPPacket, "hwlen", arpp_hlen, 0);
    rb_define_method(cARPPacket, "plen", arpp_plen, 0);
    rb_define_method(cARPPacket, "op_code", arpp_op, 0);
    rb_define_method(cARPPacket, "sender_hw", arpp_s_hw, 0);
    rb_define_method(cARPPacket, "sender_ip", arpp_s_ip, 0);
    rb_define_method(cARPPacket, "target_hw", arpp_t_hw, 0);
    rb_define_method(cARPPacket, "target_ip", arpp_t_ip, 0);
}
