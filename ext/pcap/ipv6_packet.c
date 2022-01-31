/*
 *  ipv6_packet.c
 */

#include "ruby_pcap.h"

VALUE cIPv6Packet;

#define CheckTruncateIpv6(pkt, need) CheckTruncate(pkt, pkt->hdr.layer3_off, need, "truncated IPv6")
#define IPV6_HL 40

VALUE
setup_ipv6_packet(pkt, nl_len)
     struct packet_object *pkt;
     int nl_len;
{
    VALUE class;

    class = cIPv6Packet;
    pkt->hdr.layer4_off = pkt->hdr.layer3_off + IPV6_HL;
    switch (IPV6_HDR(pkt)->ip6_nxt) {
      case IPPROTO_TCP:
        DEBUG_PRINT("setup_tcpv6_packet");
        class = setup_tcpv6_packet(pkt, nl_len - IPV6_HL);
        break;
      case IPPROTO_UDP:
        DEBUG_PRINT("setup_udpv6_packet");
        class = setup_udpv6_packet(pkt, nl_len - IPV6_HL);
        break;
      case IPPROTO_ICMPV6:
        DEBUG_PRINT("setup_icmpv6_packet");
        class = setup_icmpv6_packet(pkt);
        break;
    }
    return class;
}

#define IPV6P_METHOD(func, val) \
static VALUE\
(func)(self)\
     VALUE self;\
{\
    struct ip6_hdr *ip;\
\
    DEBUG_PRINT(#func);\
    ip = IPV6_HDR_OBJ(self);\
    return (val);\
}

IPV6P_METHOD(ipp_ver, INT2FIX(ip->ip6_vfc >> 4))
/*
The bits of this field hold two values.
The six most-significant bits hold the Differentiated Services (DS) field, which is used to classify packets.
Currently, all standard DS fields end with a '0' bit. Any DS field that ends with two '1' bits is intended for local or experimental use.[4]
The remaining two bits are used for Explicit Congestion Notification (ECN);
priority values subdivide into ranges: traffic where the source provides congestion control and non-congestion control traffic.
*/
IPV6P_METHOD(ipp_tc,  INT2FIX((ntohl(ip->ip6_flow) & 0x0FF00000) >> 20))
IPV6P_METHOD(ipp_ds,  INT2FIX((ntohl(ip->ip6_flow) & 0x0FF00000) >> 22))
IPV6P_METHOD(ipp_ecn, INT2FIX((ntohl(ip->ip6_flow) & 0x00300000) >> 20))
IPV6P_METHOD(ipp_fl,  INT2FIX(ntohl(ip->ip6_flow) & 0x000FFFFF))
IPV6P_METHOD(ipp_pl,  INT2FIX(ntohs(ip->ip6_plen)))
IPV6P_METHOD(ipp_nh,  INT2FIX(ip->ip6_nxt))
IPV6P_METHOD(ipp_hl,  INT2FIX(ip->ip6_hlim))


static VALUE
ipp_truncated(self)
     VALUE self;
{
    struct packet_object *pkt;
    struct ip6_hdr *ip;
    GetPacket(self, pkt);
    ip = IPV6_HDR(pkt);
    if IsTruncated(pkt, pkt->hdr.layer3_off, ntohs(ip->ip6_plen))
        return Qtrue;
    return Qfalse;
}

static VALUE
ipp_data(self)
     VALUE self;
{
    struct packet_object *pkt;
    struct ip6_hdr *ip;
    int len;

    GetPacket(self, pkt);
    ip = IPV6_HDR(pkt);
    CheckTruncateIpv6(pkt, 20);
    len = pkt->hdr.pkthdr.caplen - pkt->hdr.layer3_off - IPV6_HL;
    return rb_str_new((u_char *)ip + IPV6_HL, len);
}

/*
 * IPv6Address
 */

static VALUE
ipp_src_i(self)
    VALUE self;
{
  struct ip6_hdr *ip;
  ip = (struct ip6_hdr *)IPV6_HDR_OBJ(self);
  return rb_integer_unpack(ip->ip6_src.s6_addr, 16, 1, 0, INTEGER_PACK_BIG_ENDIAN);
}

static VALUE
ipp_src_s(self)
  VALUE self;
{
  struct ip6_hdr *ip;
  char buff[INET6_ADDRSTRLEN];
  ip = (struct ip6_hdr *)IPV6_HDR_OBJ(self);

  inet_ntop(AF_INET6, ip->ip6_src.s6_addr, buff, INET6_ADDRSTRLEN);
  return rb_str_new2(buff);
}

static VALUE
ipp_dst_i(self)
    VALUE self;
{
  struct ip6_hdr *ip;
  ip = IPV6_HDR_OBJ(self);
  return rb_integer_unpack(ip->ip6_dst.s6_addr, 16, 1, 0, INTEGER_PACK_BIG_ENDIAN);
}

static VALUE
ipp_dst_s(self)
  VALUE self;
{
  char buff[INET6_ADDRSTRLEN];
  struct ip6_hdr *ip;
  ip = IPV6_HDR_OBJ(self);

  inet_ntop(AF_INET6, ip->ip6_dst.s6_addr, buff, INET6_ADDRSTRLEN);
  return rb_str_new2(buff);
}

void
Init_ipv6_packet(void)
{
    DEBUG_PRINT("Init_ipv6_packet");

    cIPv6Packet = rb_define_class_under(mPcap, "IPv6Packet", cPacket);

    rb_define_method(cIPv6Packet, "ip_ver", ipp_ver, 0);
    rb_define_method(cIPv6Packet, "ip_tc", ipp_tc, 0);
    rb_define_method(cIPv6Packet, "ip_ds", ipp_ds, 0);
    rb_define_method(cIPv6Packet, "ip_ecn", ipp_ecn, 0);
    rb_define_method(cIPv6Packet, "ip_fl", ipp_fl, 0); /* IPv6 flow label */
    rb_define_method(cIPv6Packet, "ip_pl", ipp_pl, 0); /* IPv6 Payload length */
    rb_define_method(cIPv6Packet, "ip_nh", ipp_nh, 0); /* IPv6 Next header */
    rb_define_method(cIPv6Packet, "ip_hl", ipp_hl, 0); /* IPv6 Hop limit */
    rb_define_method(cIPv6Packet, "src_s", ipp_src_s, 0);
    rb_define_method(cIPv6Packet, "dst_s", ipp_dst_s, 0);
    rb_define_method(cIPv6Packet, "src_i", ipp_src_i, 0);
    rb_define_method(cIPv6Packet, "dst_i", ipp_dst_i, 0);
    rb_define_method(cIPv6Packet, "ip_data", ipp_data, 0);
    rb_define_method(cIPv6Packet, "ip_truncated?", ipp_truncated, 0);
}
