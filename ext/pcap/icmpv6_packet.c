/*
 *  icmpv6_packet.c
 */

#include "ruby_pcap.h"

#define ICMPV6_HDR(pkt)  ((struct icmp6_hdr *)LAYER4_HDR(pkt))
#define ICMP_CAPLEN(pkt) (pkt->hdr.pkthdr.caplen - pkt->hdr.layer4_off)

VALUE cICMPv6Packet;

#define CheckTruncateICMP(pkt, need) CheckTruncate(pkt, pkt->hdr.layer4_off, need, "truncated ICMPv6")


VALUE
setup_icmpv6_packet(pkt)
  struct packet_object *pkt;
{
    return cICMPv6Packet;
}


#define ICMPP_METHOD(func, need, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct packet_object *pkt;\
    struct icmp6_hdr *icmp;\
    GetPacket(self, pkt);\
    CheckTruncateICMP(pkt, (need));\
    icmp = ICMPV6_HDR(pkt);\
    return (val);\
}

/*
 * Common methods based on icmp6_hdr
 */

ICMPP_METHOD(icmpp_type,   1, INT2FIX(icmp->icmp6_type))
ICMPP_METHOD(icmpp_code,   2, INT2FIX(icmp->icmp6_code))
ICMPP_METHOD(icmpp_cksum,  4, INT2FIX(ntohs(icmp->icmp6_cksum)))
/* 4 Bytes is the common ICMPv6 Header*/
ICMPP_METHOD(icmppv6_data, 5, rb_str_new(icmp->icmp6_data8, ICMP_CAPLEN(pkt)-4))


static VALUE
icmpp_csumokv6(self)
     VALUE self;
{
    struct packet_object *pkt;
    struct ip6_hdr *ip;
    struct icmp6_hdr *icmp;
    GetPacket(self, pkt);
    ip = IPV6_HDR(pkt);
    icmp = ICMPV6_HDR(pkt);

    long sum = 0;
    unsigned short *temp = (unsigned short *)icmp;
    int len = ntohs(ip->ip6_plen); // length of ip data
    int csum = ntohs(icmp->icmp6_cksum); // keep the checksum in packet
    unsigned short *ip_src = (void *)&ip->ip6_src.s6_addr;
    unsigned short *ip_dst = (void *)&ip->ip6_dst.s6_addr;

    // ICMPv6 now inclides pseudo header sum
    int i = 1;
    for (i = 0; i < 8; i++) {
      sum += ntohs(*(ip_src));
      sum += ntohs(*(ip_dst));
      ip_src++;
      ip_dst++;
    }
    sum += 58; // ICMPv6 next header value
    sum += len;

    icmp->icmp6_cksum = 0;
    while(len > 1){
      sum += ntohs(*temp++);
      len -= 2;
    }
    if(len)
      sum += ntohs((unsigned short) *((unsigned char *)temp));
    while(sum>>16)
      sum = (sum & 0xFFFF) + (sum >> 16);
    unsigned short answer = ~sum;

    icmp->icmp6_cksum = csum; //restore the checkum in packet
    if (DEBUG_CHECKSUM)
      printf("ICMP csum in packet:%d should be %d\n", csum, answer);
    if (answer == csum)
      return Qtrue;
    return Qfalse;
}


void
Init_icmpv6_packet(void)
{

    cICMPv6Packet = rb_define_class_under(mPcap, "ICMPv6Packet", cIPv6Packet);

    rb_define_method(cICMPv6Packet, "icmp_type",     icmpp_type, 0);
    rb_define_method(cICMPv6Packet, "icmp_code",     icmpp_code, 0);
    rb_define_method(cICMPv6Packet, "icmp_cksum",    icmpp_cksum, 0);
    rb_define_method(cICMPv6Packet, "icmp_csum_ok?", icmpp_csumokv6, 0);
    rb_define_method(cICMPv6Packet, "icmp_data",     icmppv6_data, 0);
}
