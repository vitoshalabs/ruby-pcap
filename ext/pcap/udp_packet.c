/*
 *  udp_packet.c
 *
 *  $Id: udp_packet.c,v 1.1.1.1 1999/10/27 09:54:38 fukusima Exp $
 *
 *  Copyright (C) 1999  Masaki Fukushima
 */

#include "ruby_pcap.h"
#include <limits.h>

#define UDP_HDR(pkt)    ((struct udphdr *)LAYER4_HDR(pkt))
#define UDP_DATA(pkt)   ((u_char *)LAYER5_HDR(pkt))
#define UDP_LENGTH(pkt) (ntohs(UDP_HDR(pkt)->uh_ulen))

VALUE cUDPPacket;

#define CheckTruncateUdp(pkt, need) \
    CheckTruncate(pkt, pkt->hdr.layer4_off, need, "truncated UDP")

VALUE
setup_udp_packet(pkt, tl_len)
     struct packet_object *pkt;
     int tl_len;
{
    VALUE class;

    DEBUG_PRINT("setup_udp_packet");

    class = cUDPPacket;
    if (tl_len > 8) {
        int hl = 8;
        int layer5_len;

        tl_len = MIN(tl_len, UDP_LENGTH(pkt));
        layer5_len = tl_len - hl;
        if (layer5_len > 0) {
            pkt->hdr.layer5_off = pkt->hdr.layer4_off + hl;
            /* upper layer */
        }
    }
    return class;
}

#define UDPP_METHOD(func, need, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct packet_object *pkt;\
    struct udphdr *udp;\
    DEBUG_PRINT(#func);\
    GetPacket(self, pkt);\
    CheckTruncateUdp(pkt, (need));\
    udp = UDP_HDR(pkt);\
    return (val);\
}

UDPP_METHOD(udpp_sport,   2, INT2FIX(ntohs(udp->uh_sport)))
UDPP_METHOD(udpp_dport,   4, INT2FIX(ntohs(udp->uh_dport)))
UDPP_METHOD(udpp_len,     6, INT2FIX(ntohs(udp->uh_ulen)))
UDPP_METHOD(udpp_sum,     8, INT2FIX(ntohs(udp->uh_sum)))

static VALUE
udpp_data(self)
    VALUE self;
{
    struct packet_object *pkt;
    int len;

    DEBUG_PRINT("udpp_data");
    GetPacket(self, pkt);
    CheckTruncateUdp(pkt, 8);

    if (pkt->hdr.layer5_off == OFF_NONEXIST) return Qnil;

    len = MIN(Caplen(pkt, pkt->hdr.layer5_off), UDP_LENGTH(pkt)-8);
    return rb_str_new(UDP_DATA(pkt), len);
}

static VALUE
udpp_csumok(self)
     VALUE self;
{
    struct packet_object *pkt;
    struct ip *ip;
    struct udphdr *udp;
    GetPacket(self, pkt);
    ip = IP_HDR(pkt);
    udp = UDP_HDR(pkt);
    unsigned short *ip_src = (void *)&ip->ip_src.s_addr;
    unsigned short *ip_dst = (void *)&ip->ip_dst.s_addr;
    long sum = 0;
    unsigned short answer = 0;
    unsigned short *temp = (unsigned short *)udp;
    int len = ntohs(ip->ip_len) - ip->ip_hl*4; // length of ip data
    int csum = ntohs(udp->uh_sum); // keep the checksum in packet

    // pseudo header sum
    sum += ntohs(*(ip_src++));
    sum += ntohs(*ip_src);
    sum += ntohs(*(ip_dst++));
    sum += ntohs(*ip_dst);
    sum += 17;
    sum += len;
    // set checksum to zero and sum
    udp->uh_sum = 0;
    while (len > 1){
      sum += ntohs(*temp++);
      len -= 2;
    }
    if (len)
      sum += ntohs((unsigned short) *((unsigned char *)temp));
    while(sum>>16)
      sum = (sum & 0xFFFF) + (sum >> 16);

    answer = ~sum;
    if (answer == 0)
      answer = ~answer;
    udp->uh_sum = csum; //restore the checkum in packet
    if (DEBUG_CHECKSUM)
      printf("UDP csum in packet:%d should be %d\n", csum, answer);
    if (answer == csum)
      return Qtrue;
    return Qfalse;
}
static VALUE
udpp_truncated(self)
     VALUE self;
{
    struct packet_object *pkt;
    struct ip *ip;
    struct udphdr *udp;
    GetPacket(self, pkt);
    ip = IP_HDR(pkt);
    udp = UDP_HDR(pkt);
    if IsTruncated(pkt, pkt->hdr.layer3_off, ip->ip_hl * 4 + ntohs(udp->uh_ulen))
        return Qtrue;
    return Qfalse;
}

void
Init_udp_packet(void)
{
    DEBUG_PRINT("Init_udp_packet");

    /* define class UdpPacket */
    cUDPPacket = rb_define_class_under(mPcap, "UDPPacket", cIPPacket);

    rb_define_method(cUDPPacket, "udp_sport", udpp_sport, 0);
    rb_define_method(cUDPPacket, "sport", udpp_sport, 0);
    rb_define_method(cUDPPacket, "udp_dport", udpp_dport, 0);
    rb_define_method(cUDPPacket, "dport", udpp_dport, 0);
    rb_define_method(cUDPPacket, "udp_len", udpp_len, 0);
    rb_define_method(cUDPPacket, "udp_sum", udpp_sum, 0);
    rb_define_method(cUDPPacket, "udp_data", udpp_data, 0);
    rb_define_method(cUDPPacket, "udp_csum_ok?", udpp_csumok, 0);
    rb_define_method(cUDPPacket, "udp_truncated?", udpp_truncated, 0);
}
