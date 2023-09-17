/*
* H.323/H.245 connection tracking helper
* (c) 2005 Max Kellermann <max@duempel.org>
*
* Based on the 'brute force' H.323 connection tracking module by
* Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
*/


#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <net/tcp.h>

#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ip_conntrack_core.h>
#include <linux/netfilter_ipv4/ip_conntrack_helper.h>
#include <linux/netfilter_ipv4/ip_conntrack_tuple.h>
#include <linux/netfilter_ipv4/ip_conntrack_h323.h>

#include "asn1_per.h"

/* This is slow, but it's simple. --RR */
static char h245_buffer[65536];

static DEFINE_SPINLOCK(ip_h245_lock);

struct module *ip_conntrack_h245 = THIS_MODULE;

int (*ip_nat_h245_hook)(struct sk_buff **pskb,
                        enum ip_conntrack_info ctinfo,
                        unsigned int offset,
                        struct ip_conntrack_expect *exp);
EXPORT_SYMBOL_GPL(ip_nat_h245_hook);

#if 0
#define DEBUGP printk
#else
#define DEBUGP(format, args...)
#endif

/**
 * Skip an H.245 NonStandardIdentifier, discarding its value.
 */
static void h245_skip_nonstandard_id(struct asn1_per_buffer *bb)
{
    unsigned choice;

    choice = asn1_per_read_bits(bb, 1);
    switch (choice)
    {
        case 0:
            asn1_per_skip_object_id(bb);
            break;

        case 1:
            asn1_per_read_unsigned(bb, 0, 255);
            asn1_per_read_unsigned(bb, 0, 255);
            asn1_per_read_unsigned(bb, 0, 65535);
            break;
    }
}

/**
 * Skip an H.245 NonStandardParameter, discarding its value.
 */
static void h245_skip_nonstandard_param(struct asn1_per_buffer *bb)
{
    h245_skip_nonstandard_id(bb);
    /* 
     * sailor comment below line on 2007-04-11 
     * Since some netmeeting will not send the 4 bytes TPKT header in the tcp data
     */
    //asn1_per_skip_octet_string(bb);
}

/**
 * Skip an H.245 VideoCapability, discarding its value.
 */
static void h245_skip_video_capability(struct asn1_per_buffer *bb)
{
    unsigned choice, after;

    choice = asn1_per_read_choice_header(bb, 1, 5, &after);
    DEBUGP("video_capability: choice=%u after=%u error=%d\n",
           choice, after, bb->error);

    if (bb->error)
        return ;

    /* XXX support the rest */
    switch (choice)
    {
        case 0:  /* nonStandard */
            h245_skip_nonstandard_param(bb);
            break;

        default:
            if (after == 0)
            {
                DEBUGP("unsupported audio_capability %u\n", choice);
                bb->error = 1;
            }
    }

    if (after > 0)
        bb->i = after;
}

/**
 * Skip an H.245 AudioCapability, discarding its value.
 */
static void h245_skip_audio_capability(struct asn1_per_buffer *bb)
{
    unsigned choice, after;

    choice = asn1_per_read_choice_header(bb, 1, 14, &after);
    DEBUGP("audio_capability: audio_capability=%u after=%u error=%d\n", choice, after, bb->error);

    if (bb->error)
        return ;

    /* XXX support the rest */
    switch (choice)
    {
            unsigned value;

        case 0:  /* nonStandard */
            h245_skip_nonstandard_param(bb);
            break;

        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 11:
        case 14:
        case 17:
            value = asn1_per_read_unsigned(bb, 1, 256);
            DEBUGP("value %u = %u\n", choice, value);
            break;
        default:
            if (after == 0)
            {
                DEBUGP("unsupported audio_capability %u\n", choice);
                bb->error = 1;
            }
    }

    if (after > 0)
        bb->i = after;
}

/**
 * Skip an H.245 DataType, discarding its value.
 */
static void h245_skip_data_type(struct asn1_per_buffer *bb)
{
    unsigned choice, after;

    choice = asn1_per_read_choice_header(bb, 1, 6, &after);

    if (bb->error)
        return ;

    /* XXX support the rest */
    switch (choice)
    {
        case 0:  /* nonStandard */
            h245_skip_nonstandard_param(bb);
            break;

        case 1:  /* nullData */
            break;

        case 2:  /* videoData */
            h245_skip_video_capability(bb);
            break;

        case 3:  /* audioData */
            h245_skip_audio_capability(bb);
            break;

        default:
            if (after == 0)
            {
                DEBUGP("unsupported data_type %u\n", choice);
                bb->error = 1;
            }
    }

    if (after > 0)
        bb->i = after;
}

/**
 * Parse an H.245 UnicastAddress and return the position of the IP
 * address (if present). Returns 1 on success.
 */
static int h245_parse_unicast_address(struct asn1_per_buffer *bb, unsigned *i,
                                      u_int32_t *ip, u_int16_t *port)
{
    unsigned choice, after;

    choice = asn1_per_read_choice_header(bb, 1, 5, &after);
    DEBUGP("Parsing UnicastAddress choice=%u after=%u\n", choice, after);
    switch (choice)
    {
        case 0:  /* iPAddress */
            asn1_per_read_bit(bb); /* XXX use this bit */
            asn1_per_byte_align(bb);
            *i = bb->i;
            asn1_per_read_bytes(bb, ip, sizeof(*ip));
            asn1_per_read_bytes(bb, port, sizeof(*port));
            return !bb->error;
        default:
            if (after == 0)
            {
                DEBUGP("UnicastAddress %u not yet supported\n", choice);
                bb->error = 1;
            }
            else
            {
                bb->i = after;
            }
            return 0;
    }
}

/**
 * Parse an H.245 TransportAddress and return the position of the
 * Unicast IP address (if present). Returns 1 on success.
 */
static int h245_parse_transport_address(struct asn1_per_buffer *bb, unsigned *i,
                                        u_int32_t *ip, u_int16_t *port)
{
    unsigned choice, after;

    choice = asn1_per_read_choice_header(bb, 1, 2, &after);
    switch (choice)
    {
        case 0:  /* UnicastAddress */
            return h245_parse_unicast_address(bb, i, ip, port);
        case 1:  /* MulticastAddress */
            /* XXX */
            DEBUGP("MulticastAddress not yet supported\n");
            bb->error = 1;
            return 0;
        default:
            if (after == 0)
            {
                DEBUGP("ERROR7\n");
                bb->error = 1;
            }
            else
            {
                bb->i = after;
            }
            return 0;
    }
}

/**
 * Skip an H.245 TerminalLabel, discarding its value.
 */
static void h245_skip_terminal_label(struct asn1_per_buffer *bb)
{
    struct asn1_per_sequence_header hdr;

    asn1_per_read_sequence_header(bb, 1, 0, &hdr);

    /* mcuNumber */
    asn1_per_read_unsigned(bb, 0, 192);
    /* terminalNumber */
    asn1_per_read_unsigned(bb, 0, 192);

    asn1_per_skip_sequence_extension(bb, &hdr);
}

/**
 * Parse an H.245 H2250LogicalChannelParameters request packet and
 * handle NAT/expectations for the logical channel address.
 */
static int h245_parse_h2250_lchannel_params(struct sk_buff **pskb,
        struct ip_conntrack *ct,
        enum ip_conntrack_info ctinfo,
        struct asn1_per_buffer *bb)
{
    struct asn1_per_sequence_header hdr;
    unsigned session_id;
    int need_out = 0; //a func out sign ***by hagi

    asn1_per_read_sequence_header(bb, 1, 10, &hdr);

    /* nonStandard */
    if (asn1_per_bitmap_get(&hdr.present, 0))
        h245_skip_nonstandard_param(bb);

    /* sessionID */
    session_id = asn1_per_read_unsigned(bb, 0, 255);

    /* associatedSessionID */
    if (asn1_per_bitmap_get(&hdr.present, 1))
        asn1_per_read_unsigned(bb, 1, 255);

    /* mediaChannel */
    DEBUGP("lchannel_params mediaChannel: i=%u bit=%u\n", bb->i, bb->bit);
    if (asn1_per_bitmap_get(&hdr.present, 2))
    {
        int dir = CTINFO2DIR(ctinfo);
        struct ip_conntrack_expect *exp;
        int ret;
        unsigned i;
        u_int32_t ip;
        u_int16_t port;

        ret = h245_parse_transport_address(bb, &i, &ip, &port);
        if (ret)
            DEBUGP("mediaChannel IPv4 address: %u.%u.%u.%u:%u\n",
                   NIPQUAD(ip), ntohs(port));

        if (ret && ip == ct->tuplehash[dir].tuple.src.ip)
        {
            /* match found: create an expectation */
            exp = ip_conntrack_expect_alloc(ct);
            if (exp == NULL)
                return NF_ACCEPT;

            exp->tuple = ((struct ip_conntrack_tuple)
                          {
                              {
                                  ct->tuplehash[!dir].tuple.src.ip,
                                  { 0 }
                              },
                              { ct->tuplehash[!dir].tuple.dst.ip,
                                { .udp = { port } },
                                IPPROTO_UDP }
                          }
                         );
            exp->mask = ((struct ip_conntrack_tuple)
                         {
                             {
                                 0xFFFFFFFF, { 0 }
                             },
                             { 0xFFFFFFFF, { .udp = { 0xFFFF } }, 0xFF }
                         }
                        );

            exp->master = ct;

            /* call NAT hook and register expectation */
            if (ip_nat_h245_hook != NULL)
            {
                ret = ip_nat_h245_hook(pskb, ctinfo, i, exp);
            }
            else
            {
                /* Can't expect this?  Best to drop packet now. */
                if (ip_conntrack_expect_related(exp) != 0)
                {
                    ret = NF_DROP;
                }
                else
                {
                    ret = NF_ACCEPT;
                }
            }

            ip_conntrack_expect_put(exp);

            if (ret != NF_ACCEPT)
                return ret;
        }
        else
        { //add the fragment case ***by hagi 06-4-24
            int dir = CTINFO2DIR(ctinfo);
            struct ip_conntrack_expect *exp;
            int ret;
            unsigned i;
            const unsigned char *data; //need add...
            const unsigned char *data_limit;
            u_int32_t ip;
            u_int16_t port;
            unsigned j, dataoff, datalen; //need add...
            struct tcphdr _tcph, *tcph;

            tcph = skb_header_pointer(*pskb, (*pskb)->nh.iph->ihl * 4,
                                      sizeof(_tcph), &_tcph);
            dataoff = (*pskb)->nh.iph->ihl * 4 + tcph->doff * 4;
            datalen = (*pskb)->len - dataoff;
            data = skb_header_pointer((*pskb), dataoff,
                                      datalen, h245_buffer);

            data_limit = (unsigned char *) data + datalen;
            for (j = 0;data < (data_limit - 5);data++, j++)
            {
                ip = *((u_int32_t *)data); //memcpy(&ip,&data[j],4);
                if (ip == ct->tuplehash[dir].tuple.src.ip)
                {
                    /* match found: create an expectation */
                    exp = ip_conntrack_expect_alloc(ct);
                    if (exp == NULL)
                        return NF_ACCEPT;

                    port = *((u_int16_t *)(data + 4));
                    exp->tuple = ((struct ip_conntrack_tuple)
                                  {
                                      {
                                          ct->tuplehash[!dir].tuple.src.ip,
                                          { 0 }
                                      },
                                      { ct->tuplehash[!dir].tuple.dst.ip,
                                        { .udp = { port } },
                                        IPPROTO_UDP }
                                  }
                                 );
                    exp->mask = ((struct ip_conntrack_tuple)
                                 {
                                     {
                                         0xFFFFFFFF, { 0 }
                                     },
                                     { 0xFFFFFFFF, { .udp = { 0xFFFF } }, 0xFF }
                                 }
                                );

                    exp->master = ct;

                    /* call NAT hook and register expectation */
                    if (ip_nat_h245_hook != NULL)
                    {
                        ret = ip_nat_h245_hook(pskb, ctinfo, j, exp);
                    }
                    else
                    {
                        /* Can't expect this?  Best to drop packet now. */
                        if (ip_conntrack_expect_related(exp) != 0)
                        {
                            ret = NF_DROP;
                        }
                        else
                        {
                            ret = NF_ACCEPT;
                        }
                    }
                    ip_conntrack_expect_put(exp);

                    need_out += 1;
                }
            }
        }
    }
    else
    { //add the fragment case   ***by hagi 06-4-24
        int dir = CTINFO2DIR(ctinfo);
        struct ip_conntrack_expect *exp;
        int ret;
        unsigned i;
        const unsigned char *data; //need add...
        const unsigned char *data_limit;
        u_int32_t ip;
        u_int16_t port;
        unsigned j, dataoff, datalen; //need add...
        struct tcphdr _tcph, *tcph;

        tcph = skb_header_pointer(*pskb, (*pskb)->nh.iph->ihl * 4,
                                  sizeof(_tcph), &_tcph);
        dataoff = (*pskb)->nh.iph->ihl * 4 + tcph->doff * 4;
        datalen = (*pskb)->len - dataoff;
        data = skb_header_pointer((*pskb), dataoff,
                                  datalen, h245_buffer);

        data_limit = (unsigned char *) data + datalen;
        for (j = 0;data < (data_limit - 5);data++, j++)
        {
            ip = *((u_int32_t *)data); //memcpy(&ip,&data[j],4);
            if (ip == ct->tuplehash[dir].tuple.src.ip)
            {
                /* match found: create an expectation */
                exp = ip_conntrack_expect_alloc(ct);
                if (exp == NULL)
                    return NF_ACCEPT;

                port = *((u_int16_t *)(data + 4));
                exp->tuple = ((struct ip_conntrack_tuple)
                              {
                                  {
                                      ct->tuplehash[!dir].tuple.src.ip,
                                      { 0 }
                                  },
                                  { ct->tuplehash[!dir].tuple.dst.ip,
                                    { .udp = { port } },
                                    IPPROTO_UDP }
                              }
                             );
                exp->mask = ((struct ip_conntrack_tuple)
                             {
                                 {
                                     0xFFFFFFFF, { 0 }
                                 },
                                 { 0xFFFFFFFF, { .udp = { 0xFFFF } }, 0xFF }
                             }
                            );

                exp->master = ct;

                /* call NAT hook and register expectation */
                if (ip_nat_h245_hook != NULL)
                {
                    ret = ip_nat_h245_hook(pskb, ctinfo, j, exp);
                }
                else
                {
                    /* Can't expect this?  Best to drop packet now. */
                    if (ip_conntrack_expect_related(exp) != 0)
                    {
                        ret = NF_DROP;
                    }
                    else
                    {
                        ret = NF_ACCEPT;
                    }
                }
                ip_conntrack_expect_put(exp);

                need_out += 1;
            }
        }

        if (need_out > 0)
            return ret;
    }
    /* mediaGuaranteedDelivery */
    if (asn1_per_bitmap_get(&hdr.present, 3))
        asn1_per_read_bit(bb);

    /* mediaControlChannel */
    DEBUGP("lchannel_params controlChannel: i=%u bit=%u\n", bb->i, bb->bit);
    if (asn1_per_bitmap_get(&hdr.present, 4))
    {
        int dir = CTINFO2DIR(ctinfo);
        struct ip_conntrack_expect *exp;
        int ret;
        unsigned i;
        u_int32_t ip;
        u_int16_t port;

        ret = h245_parse_transport_address(bb, &i, &ip, &port);
        if (ret)
            DEBUGP("mediaControlChannel IPv4 address: %u.%u.%u.%u:%u\n",
                   NIPQUAD(ip), ntohs(port));
        if (ret && ip == ct->tuplehash[dir].tuple.src.ip)
        {
            /* match found: create an expectation */
            exp = ip_conntrack_expect_alloc(ct);
            if (exp == NULL)
                return NF_ACCEPT;

            exp->tuple = ((struct ip_conntrack_tuple)
                          {
                              {
                                  ct->tuplehash[!dir].tuple.src.ip,
                                  { 0 }
                              },
                              { ct->tuplehash[!dir].tuple.dst.ip,
                                { .udp = { port } },
                                IPPROTO_UDP }
                          }
                         );
            exp->mask = ((struct ip_conntrack_tuple)
                         {
                             {
                                 0xFFFFFFFF, { 0 }
                             },
                             { 0xFFFFFFFF, { .udp = { 0xFFFF } }, 0xFF }
                         }
                        );

            exp->master = ct;

            /* call NAT hook and register expectation */
            if (ip_nat_h245_hook != NULL)
            {
                ret = ip_nat_h245_hook(pskb, ctinfo, i, exp);
            }
            else
            {
                /* Can't expect this?  Best to drop packet now. */
                if (ip_conntrack_expect_related(exp) != 0)
                {
                    ret = NF_DROP;
                }
                else
                {
                    ret = NF_ACCEPT;
                }
            }

            ip_conntrack_expect_put(exp);

            if (ret != NF_ACCEPT)
                return ret;
        }
    }

    /* mediaControlGuaranteedDelivery */
    if (asn1_per_bitmap_get(&hdr.present, 5))
        asn1_per_read_bit(bb);

    /* silenceSuppression */
    if (asn1_per_bitmap_get(&hdr.present, 6))
        asn1_per_read_bit(bb);

    /* destination */
    if (asn1_per_bitmap_get(&hdr.present, 7))
        h245_skip_terminal_label(bb);

    /* dynamicRTPPayloadType */
    if (asn1_per_bitmap_get(&hdr.present, 8))
        asn1_per_read_unsigned(bb, 96, 127);

    /* mediaPacketization */
    if (asn1_per_bitmap_get(&hdr.present, 9))
    {
        unsigned choice, after;

        choice = asn1_per_read_choice_header(bb, 1, 1, &after);
        switch (choice)
        {
            case 0:  /* h261aVideoPacketization */
                break;

            default:
                if (after == 0)
                {
                    DEBUGP("ERROR7\n");
                    bb->error = 1;
                    return NF_ACCEPT;
                }

                bb->i = after;
        }
    }

    /* XXX */

    asn1_per_skip_sequence_extension(bb, &hdr);

    return NF_ACCEPT;
}

/**
 * Parse an H.245 OpenLogicalChannel request packet and handle
 * NAT/expectations for the logical channel address.
 */
static int h245_parse_open_lchannel(struct sk_buff **pskb,
                                    struct ip_conntrack *ct,
                                    enum ip_conntrack_info ctinfo,
                                    struct asn1_per_buffer *bb)
{
    struct asn1_per_sequence_header hdr, hdr2;
    unsigned forwardLogicalChannelNumber;
    unsigned choice, after;

    asn1_per_read_sequence_header(bb, 1, 1, &hdr);

    forwardLogicalChannelNumber = asn1_per_read_unsigned(bb, 1, 65535);

    /* entering forwardLogicalChannelParameters */
    asn1_per_read_sequence_header(bb, 1, 1, &hdr2);
    if (asn1_per_bitmap_get(&hdr2.present, 0))
        asn1_per_read_unsigned(bb, 0, 65535);

    h245_skip_data_type(bb);

    /* multiplexParameters */
    choice = asn1_per_read_choice_header(bb, 1, 3, &after);
    if (bb->error)
        return NF_ACCEPT;

    switch (choice)
    {
        case 3:  /* h2250LogicalChannelParameters */
            h245_parse_h2250_lchannel_params(pskb, ct, ctinfo, bb);
            break;
        default:
            //let the kernel to parse frag's params ***by hagi 06-4-24
            h245_parse_h2250_lchannel_params(pskb, ct, ctinfo, bb);
            break;

            /*		if (after == 0) {
            			DEBUGP("unsupported multiplex_parameter %u\n", choice);
            			bb->error = 1;
            			return NF_ACCEPT;
            		}*/
    }

    if (bb->error)
        return NF_ACCEPT;

    if (after > 0)
        bb->i = after;

    asn1_per_skip_sequence_extension(bb, &hdr2);

    /* leaving multiplexParameters, forwardLogicalChannelParameters */

    /* reverseLogicalChannelParameters */
    if (asn1_per_bitmap_get(&hdr.present, 0))
    {
        asn1_per_read_sequence_header(bb, 1, 1, &hdr2);

        h245_skip_data_type(bb);

        /* multiplexParameters */
        if (asn1_per_bitmap_get(&hdr2.present, 0))
        {
            choice = asn1_per_read_choice_header(bb, 1, 2, &after);
            if (bb->error)
                return NF_ACCEPT;

            DEBUGP("reverse_parameter multiplex=%u after=%u\n", choice, after);

            switch (choice)
            {
                case 2:  /* h2250LogicalChannelParameters */
                    h245_parse_h2250_lchannel_params(pskb, ct, ctinfo, bb);
                    break;
                default:
                    if (after == 0)
                    {
                        DEBUGP("unsupported multiplex_parameter %u\n", choice);
                        bb->error = 1;
                        return NF_ACCEPT;
                    }
            }

            if (bb->error)
                return NF_ACCEPT;

            if (after > 0)
                bb->i = after;
        }

        asn1_per_skip_sequence_extension(bb, &hdr2);
    }

    asn1_per_skip_sequence_extension(bb, &hdr);

    /* XXX */
    return NF_ACCEPT;
}

/**
 * Parse an H.245 request packet and handle NAT/expectations for the
 * logical channel address.
 */
static int h245_parse_request(struct sk_buff **pskb,
                              struct ip_conntrack *ct,
                              enum ip_conntrack_info ctinfo,
                              struct asn1_per_buffer *bb)
{
    unsigned choice, after;

    choice = asn1_per_read_choice_header(bb, 1, 11, &after);
    DEBUGP("H.245: message_type=%u\n", choice);
    switch (choice)
    {
        case 0: 			//this case is added by hagi for frag --06-4-24
            return h245_parse_open_lchannel(pskb, ct, ctinfo, bb);
        case 1: 			//this case is added by hagi for frag	--06-4-24
            return h245_parse_open_lchannel(pskb, ct, ctinfo, bb);
        case 3:
            return h245_parse_open_lchannel(pskb, ct, ctinfo, bb);
        default:
            return NF_ACCEPT;
    }
}

/**
 * Parse an H.245 H222LogicalChannelParameters response packet and
 * handle NAT/expectations for the logical channel address.
 */
static int h245_parse_h222_lchannel_params(struct sk_buff **pskb,
        struct ip_conntrack *ct,
        enum ip_conntrack_info ctinfo,
        struct asn1_per_buffer *bb)
{
    struct asn1_per_sequence_header hdr;

    asn1_per_read_sequence_header(bb, 1, 3, &hdr);

    if (bb->error)
        return NF_ACCEPT;

    /* resourceID */
    asn1_per_read_unsigned(bb, 0, 65535);

    /* subChannelID */
    asn1_per_read_unsigned(bb, 0, 8191);

    /* pcr-pid */
    if (asn1_per_bitmap_get(&hdr.present, 0))
        asn1_per_read_unsigned(bb, 0, 8191);

    /* programDescriptors */
    if (asn1_per_bitmap_get(&hdr.present, 1))
        asn1_per_skip_octet_string(bb);

    /* streamDescriptors */
    if (asn1_per_bitmap_get(&hdr.present, 2))
        asn1_per_skip_octet_string(bb);

    asn1_per_skip_sequence_extension(bb, &hdr);

    return NF_ACCEPT;
}

/**
 * Parse an H.245 H2250LogicalChannelAckParameters response packet and
 * handle NAT/expectations for the logical channel address.
 */
static int h245_parse_h2250_lchannel_ack_params(struct sk_buff **pskb,
        struct ip_conntrack *ct,
        enum ip_conntrack_info ctinfo,
        struct asn1_per_buffer *bb)
{
    struct asn1_per_sequence_header hdr;
    unsigned count;

    DEBUGP("entering h245_parse_h2250_lchannel_ack_params\n");

    asn1_per_read_sequence_header(bb, 1, 5, &hdr);

    /* nonStandard */
    if (asn1_per_bitmap_get(&hdr.present, 0))
    {
        count = asn1_per_read_length(bb, 0, UINT_MAX);
        while (count > 0)
        {
            h245_skip_nonstandard_param(bb);
            if (bb->error)
                return NF_ACCEPT;
        }
    }

    /* sessionID */
    if (asn1_per_bitmap_get(&hdr.present, 1))
        asn1_per_read_unsigned(bb, 1, 255);

    /* mediaChannel */
    if (asn1_per_bitmap_get(&hdr.present, 2))
    {
        int ret;
        unsigned i;
        u_int32_t ip;
        u_int16_t port;
        int dir = CTINFO2DIR(ctinfo);
        struct ip_conntrack_expect *exp;

        ret = h245_parse_transport_address(bb, &i, &ip, &port);
        DEBUGP("entering mediaChannel ret=%d i=%u ip=%x port=%u\n",
               ret, i, ip, port);
        if (ret && ip == ct->tuplehash[dir].tuple.src.ip)
        {
            /* match found: create an expectation */
            exp = ip_conntrack_expect_alloc(ct);
            if (exp == NULL)
                return NF_ACCEPT;

            exp->tuple = ((struct ip_conntrack_tuple)
                          {
                              {
                                  ct->tuplehash[!dir].tuple.src.ip,
                                  { 0 }
                              },
                              { ct->tuplehash[!dir].tuple.dst.ip,
                                { .udp = { port } },
                                IPPROTO_UDP }
                          }
                         );
            exp->mask = ((struct ip_conntrack_tuple)
                         {
                             {
                                 0xFFFFFFFF, { 0 }
                             },
                             { 0xFFFFFFFF, { .udp = { 0xFFFF } }, 0xFF }
                         }
                        );

            exp->master = ct;

            /* call NAT hook and register expectation */
            if (ip_nat_h245_hook != NULL)
            {
                ret = ip_nat_h245_hook(pskb, ctinfo, i, exp);
            }
            else
            {
                /* Can't expect this?  Best to drop packet now. */
                if (ip_conntrack_expect_related(exp) != 0)
                {
                    ret = NF_DROP;
                }
                else
                {
                    ret = NF_ACCEPT;
                }
            }

            ip_conntrack_expect_put(exp);

            if (ret != NF_ACCEPT)
                return ret;
        }
    }

    /* mediaControlChannel */
    if (asn1_per_bitmap_get(&hdr.present, 3))
    {
        int ret;
        unsigned i;
        u_int32_t ip;
        u_int16_t port;
        int dir = CTINFO2DIR(ctinfo);
        struct ip_conntrack_expect *exp;

        ret = h245_parse_transport_address(bb, &i, &ip, &port);
        DEBUGP("entering mediaControlChannel ret=%d i=%u ip=%x port=%u\n",
               ret, i, ip, port);
        if (ret && ip == ct->tuplehash[dir].tuple.src.ip)
        {
            /* match found: create an expectation */
            exp = ip_conntrack_expect_alloc(ct);
            if (exp == NULL)
                return NF_ACCEPT;

            exp->tuple = ((struct ip_conntrack_tuple)
                          {
                              {
                                  ct->tuplehash[!dir].tuple.src.ip,
                                  { 0 }
                              },
                              { ct->tuplehash[!dir].tuple.dst.ip,
                                { .udp = { port } },
                                IPPROTO_UDP }
                          }
                         );
            exp->mask = ((struct ip_conntrack_tuple)
                         {
                             {
                                 0xFFFFFFFF, { 0 }
                             },
                             { 0xFFFFFFFF, { .udp = { 0xFFFF } }, 0xFF }
                         }
                        );

            exp->master = ct;

            /* call NAT hook and register expectation */
            if (ip_nat_h245_hook != NULL)
            {
                ret = ip_nat_h245_hook(pskb, ctinfo, i, exp);
            }
            else
            {
                /* Can't expect this?  Best to drop packet now. */
                if (ip_conntrack_expect_related(exp) != 0)
                {
                    ret = NF_DROP;
                }
                else
                {
                    ret = NF_ACCEPT;
                }
            }

            ip_conntrack_expect_put(exp);

            if (ret != NF_ACCEPT)
                return ret;
        }
    }

    /* dynamicRTPPayloadType */
    if (asn1_per_bitmap_get(&hdr.present, 1))
        asn1_per_read_unsigned(bb, 96, 127);

    asn1_per_skip_sequence_extension(bb, &hdr);

    return NF_ACCEPT;
}

/**
 * Parse an H.245 OpenLogicalChannelAck response packet and handle
 * NAT/expectations for the logical channel address.
 */
static int h245_parse_open_lchannel_ack(struct sk_buff **pskb,
                                        struct ip_conntrack *ct,
                                        enum ip_conntrack_info ctinfo,
                                        struct asn1_per_buffer *bb)
{
    struct asn1_per_sequence_header hdr, hdr2;
    struct asn1_per_sequence_extension_header ext;
    unsigned forwardLogicalChannelNumber;
    unsigned choice, after, after2, i;

    asn1_per_read_sequence_header(bb, 1, 1, &hdr);

    forwardLogicalChannelNumber = asn1_per_read_unsigned(bb, 1, 65535);
    DEBUGP("forwardLogicalChannelNumber=%u\n", forwardLogicalChannelNumber);

    /* reverseLogicalChannelParameters */
    if (asn1_per_bitmap_get(&hdr.present, 0))
    {
        DEBUGP("reverseLogicalChannelParameters present\n");
        asn1_per_read_sequence_header(bb, 1, 2, &hdr2);

        /* reverseLogicalChannelNumber */
        asn1_per_read_unsigned(bb, 1, 65535);

        /* portNumber */
        if (asn1_per_bitmap_get(&hdr.present, 0))
            asn1_per_read_unsigned(bb, 0, 65535);

        /* multiplexParameters */
        if (asn1_per_bitmap_get(&hdr2.present, 1))
        {
            choice = asn1_per_read_choice_header(bb, 1, 1, &after);
            if (bb->error)
                return NF_ACCEPT;

            switch (choice)
            {
                case 0:  /* h222LogicalChannelParameters */
                    h245_parse_h222_lchannel_params(pskb, ct,
                                                    ctinfo, bb);
                    break;
                case 1:  /* h2250LogicalChannelParameters */
                    h245_parse_h2250_lchannel_params(pskb, ct,
                                                     ctinfo, bb);
                    break;
                default:
                    if (after == 0)
                    {
                        DEBUGP("unsupported multiplex_parameter %u\n", choice);
                        bb->error = 1;
                        return NF_ACCEPT;
                    }
            }

            if (bb->error)
                return NF_ACCEPT;

            if (after > 0)
                bb->i = after;
        }

        asn1_per_skip_sequence_extension(bb, &hdr2);
    }

    asn1_per_read_sequence_extension_header(bb, &hdr, &ext);
    if (bb->error)
        return NF_ACCEPT;

    /* separateStack */
    if (asn1_per_bitmap_get(&ext.present, 0))
        asn1_per_skip_octet_string(bb);

    /* forwardMultiplexAckParameters */
    if (asn1_per_bitmap_get(&ext.present, 1))
    {
        DEBUGP("forwardMultiplexAckParameters present\n");

        after = asn1_per_read_octet_string_header(bb);
        DEBUGP("forwardMultiplexAckParameters present length=%u i=%u after=%u end=%u\n",
               after, bb->i, bb->i + after, bb->length);
        after += bb->i;

        choice = asn1_per_read_choice_header(bb, 1, 1, &after2);
        if (bb->error)
            return NF_ACCEPT;

        DEBUGP("entering forwardMultiplexAckParameters choice=%u after=%u\n", choice, after2);

        switch (choice)
        {
            case 0:  /* h2250LogicalChannelAckParameters */
                h245_parse_h2250_lchannel_ack_params(pskb, ct,
                                                     ctinfo, bb);
                break;
        }

        if (bb->error)
            return NF_ACCEPT;

        bb->i = after;
    }

    for (i = 2; i < ext.count; i++)
        if (asn1_per_bitmap_get(&ext.present, i))
            asn1_per_skip_octet_string(bb);

    return NF_ACCEPT;
}

/**
 * Parse an H.245 response packet and handle NAT/expectations for the
 * logical channel address.
 */
static int h245_parse_response(struct sk_buff **pskb,
                               struct ip_conntrack *ct,
                               enum ip_conntrack_info ctinfo,
                               struct asn1_per_buffer *bb)
{
    unsigned choice, after;

    choice = asn1_per_read_choice_header(bb, 1, 19, &after);
    DEBUGP("H.245: response type=%u\n", choice);
    switch (choice)
    {
        case 5:  /* openLogicalChannelAck */
            return h245_parse_open_lchannel_ack(pskb, ct, ctinfo, bb);

        default:
            return NF_ACCEPT;
    }
}

/**
 * Parse an H.245 packet and handle NAT/expectations for the logical
 * channel address.
 */
static int h245_parse(struct sk_buff **pskb,
                      struct ip_conntrack *ct,
                      enum ip_conntrack_info ctinfo,
                      struct asn1_per_buffer *bb)
{
    unsigned choice, after;

    choice = asn1_per_read_choice_header(bb, 1, 4, &after);
    DEBUGP("H.245: message_class=%u\n", choice);
    switch (choice)
    {
        case 0:
            return h245_parse_request(pskb, ct, ctinfo, bb);
        case 1:
            return h245_parse_response(pskb, ct, ctinfo, bb);
        default:
            return NF_ACCEPT;
    }
}

/**
 * Parse a TPKT/H.245 packet and handle NAT/expectations for the
 * logical channel transport address (if applicable).
 */
static int h245_parse_tpkt(struct sk_buff **pskb,
                           struct ip_conntrack *ct,
                           enum ip_conntrack_info ctinfo,
                           const unsigned char *data,
                           unsigned datalen)
{
    unsigned int i = 0;
    u_int16_t tpkt_len;
    struct asn1_per_buffer bb;

    if (i + 4 > datalen)
        return NF_ACCEPT;

    /* expect TPKT header, see RFC 1006 */
    //if (data[0] != 0x03 || data[1] != 0x00)
    //return NF_ACCEPT;

    //i += 2;

    tpkt_len = ntohs(*(u_int16_t*)(data + i));
    if (tpkt_len < datalen)
        datalen = tpkt_len;

    i += 2;

    /* parse H.245 packet (ASN.1 PER) */
    asn1_per_initialize(&bb, data, datalen, i);

    return h245_parse(pskb, ct, ctinfo, &bb);
}

static int h245_help(struct sk_buff **pskb,
                     struct ip_conntrack *ct,
                     enum ip_conntrack_info ctinfo)
{
    struct tcphdr _tcph, *tcph;
    unsigned char *data;
    unsigned dataoff, datalen;
    int ret;

    tcph = skb_header_pointer(*pskb, (*pskb)->nh.iph->ihl*4,
                              sizeof(_tcph), &_tcph);
    DEBUGP("ct_h245_help: help entered %u.%u.%u.%u:%u->%u.%u.%u.%u:%u\n",
           NIPQUAD((*pskb)->nh.iph->saddr), ntohs(tcph->source),
           NIPQUAD((*pskb)->nh.iph->daddr), ntohs(tcph->dest));
    
    /* Until there's been traffic both ways, don't look in packets. */
    if (ctinfo != IP_CT_ESTABLISHED
            && ctinfo != IP_CT_ESTABLISHED + IP_CT_IS_REPLY)
    {
        DEBUGP("ct_h245_help: Conntrackinfo = %u\n", ctinfo);
        return NF_ACCEPT;
    }

    if (tcph == NULL)
        return NF_ACCEPT;

    DEBUGP("ct_h245_help: help entered %u.%u.%u.%u:%u->%u.%u.%u.%u:%u\n",
           NIPQUAD((*pskb)->nh.iph->saddr), ntohs(tcph->source),
           NIPQUAD((*pskb)->nh.iph->daddr), ntohs(tcph->dest));

    dataoff = (*pskb)->nh.iph->ihl*4 + tcph->doff*4;
    /* No data? */
    if (dataoff >= (*pskb)->len)
    {
        DEBUGP("ct_h245_help: skblen = %u\n", (*pskb)->len);
        return NF_ACCEPT;
    }
    datalen = (*pskb)->len - dataoff;

    if (datalen < 16)
        return NF_ACCEPT;

    spin_lock_bh(&ip_h245_lock);
    data = skb_header_pointer((*pskb), dataoff,
                              datalen, h245_buffer);
    BUG_ON(data == NULL);

    ret = h245_parse_tpkt(pskb, ct, ctinfo,
                          data, datalen);

    spin_unlock_bh(&ip_h245_lock);
    return ret;
}

/* H.245 helper is not registered! */
static struct ip_conntrack_helper h245 =
    {
        .name = "H.245",
                .max_expected = 8,
                                .timeout = 240,
                                           .tuple = { .dst = { .protonum = IPPROTO_TCP } },
                                                    .mask = { .src = { .u = { 0xFFFF } },
                                                              .dst = { .protonum = 0xFF } },
                                                            .help = h245_help
                                                                };

void ip_conntrack_h245_expect(struct ip_conntrack *new,
                              struct ip_conntrack_expect *this)
{
    write_lock_bh(&ip_conntrack_lock);
    new->helper = &h245;
    DEBUGP("h225_expect: helper for %p added\n", new);
    write_unlock_bh(&ip_conntrack_lock);
}
EXPORT_SYMBOL_GPL(ip_conntrack_h245_expect);
