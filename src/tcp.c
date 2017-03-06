/*
 Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
 See the file COPYING for license details.
 
 Add document by Zhaif <zhai3516@163.com> at 2017/03/01
 */

#include <config.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#include "checksum.h"
#include "scan.h"
#include "tcp.h"
#include "util.h"
#include "nids.h"
#include "hash.h"

#if ! HAVE_TCP_STATES
enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING			/* now a valid state */
};

#endif

#define FIN_SENT 120
#define FIN_CONFIRMED 121
#define COLLECT_cc 1
#define COLLECT_sc 2
#define COLLECT_ccu 4
#define COLLECT_scu 8

#define EXP_SEQ (snd->first_data_seq + rcv->count + rcv->urg_count)

// libnids回调函数链表，register_callback时向此添加，删除同理
extern struct proc_node *tcp_procs;

// libnids存储其管理的tcp connection 的 hash table
static struct tcp_stream **tcp_stream_table;
// 上述hash table的大小， 可通过 nids_params.n_tcp_streams 参数设置
static int tcp_stream_table_size; //default = 1024

// 存储所有正在追踪的的tcp_stream的链表
static struct tcp_stream *streams_pool;
// 上述链表的最大长度，是tcp_stream_table_size 的 3/4 ，
static int max_stream;
// 当前正在追踪的tcp_stream数量
static int tcp_num = 0;

/*
 这里实质上定义了一个双链表，根据 tcp_stream 的到达时间有序排列
 tcp_latest 指向最新的 tcp_stream
 tcp_oldest 指向最旧的 tcp_stream
 */
static struct tcp_stream *tcp_latest = 0, *tcp_oldest = 0;

// 管理空闲tcp的链表，按到达时间降序排列
static struct tcp_stream *free_streams;

// 记录原始的ip header
static struct ip *ugly_iphdr;

/*
 当 nids_params.tcp_workarounds ！= 0时，
 关闭的tcp connection不会立即被释放，而是存储在这个链表
 这个链表存储的tcp_streams是有序的，按生成时间戳升序排列
 */
struct tcp_timeout *nids_tcp_timeouts = 0;


// 清空传入的 half_stream 的 list
// TODO : list 中存储的是什么？
static void purge_queue(struct half_stream * h)
{
    struct skbuff *tmp, *p = h->list;
    
    // 清空h->list，并将h->list，h->listtail 设置为空
    while (p) {
        free(p->data);
        tmp = p->next;
        free(p);
        p = tmp;
    }
    h->list = h->listtail = 0;
    h->rmem_alloc = 0; // 设置占用空间为0
}

// 向超时链表nids_tcp_timeouts 中添加刚关闭的 tcp_stream
static void
add_tcp_closing_timeout(struct tcp_stream * a_tcp)
{
    struct tcp_timeout *to;
    struct tcp_timeout *newto;
    
    // 仅当设置了tcp_workarounds时，才会添加
    if (!nids_params.tcp_workarounds)
        return;
    newto = malloc(sizeof (struct tcp_timeout));
    if (!newto)
        nids_params.no_mem("add_tcp_closing_timeout");
    newto->a_tcp = a_tcp;
    newto->timeout.tv_sec = nids_last_pcap_header->ts.tv_sec + 10;
    newto->prev = 0;
    
    // nids_tcp_timeouts 是按时间戳tv_sec升序排列的
    // 在这里将关闭的 tcp_stream 插入到链表合适的位置
    // 此操作需要遍历整个链表
    for (newto->next = to = nids_tcp_timeouts; to; newto->next = to = to->next) {
        if (to->a_tcp == a_tcp) {
            free(newto);
            return;
        }
        if (to->timeout.tv_sec > newto->timeout.tv_sec)
            break;
        newto->prev = to;
    }
    if (!newto->prev)
        nids_tcp_timeouts = newto;
    else
        newto->prev->next = newto;
    if (newto->next)
        newto->next->prev = newto;
}

// 释放超时链表 nids_tcp_timeouts 中的指定tcp_stream，如果不存在则 return
static void
del_tcp_closing_timeout(struct tcp_stream * a_tcp)
{
    struct tcp_timeout *to;
    
    if (!nids_params.tcp_workarounds)
        return;
    // 此操作需要遍历整个链表
    for (to = nids_tcp_timeouts; to; to = to->next)
        if (to->a_tcp == a_tcp)
            break;
    if (!to)
        return;
    if (!to->prev)
        nids_tcp_timeouts = to->next;
    else
        to->prev->next = to->next;
    if (to->next)
        to->next->prev = to->prev;
    free(to);
}


// 释放指定 tcp_stream
void
nids_free_tcp_stream(struct tcp_stream * a_tcp)
{
    int hash_index = a_tcp->hash_index;
    struct lurker_node *i, *j; // 指向listener的指针
    
    // 释放超时链表中的tcp_stream
    del_tcp_closing_timeout(a_tcp);
    
    // 分别释放 tcp_stream 中的 server 和 client 的 list
    purge_queue(&a_tcp->server);
    purge_queue(&a_tcp->client);
    
    // 从tcp_stream_table 中删除此 tcp_stream
    if (a_tcp->next_node)
        a_tcp->next_node->prev_node = a_tcp->prev_node;
    if (a_tcp->prev_node)
        a_tcp->prev_node->next_node = a_tcp->next_node;
    else
        tcp_stream_table[hash_index] = a_tcp->next_node;
    
    // 释放 client 和 server 的 data
    // TODO : data 存储的是什么数据？
    if (a_tcp->client.data)
        free(a_tcp->client.data);
    if (a_tcp->server.data)
        free(a_tcp->server.data);
    
    // 从 time 双链表中删除此 tcp_stream
    if (a_tcp->next_time)
        a_tcp->next_time->prev_time = a_tcp->prev_time;
    if (a_tcp->prev_time)
        a_tcp->prev_time->next_time = a_tcp->next_time;
    if (a_tcp == tcp_oldest)
        tcp_oldest = a_tcp->prev_time;
    if (a_tcp == tcp_latest)
        tcp_latest = a_tcp->next_time;
    
    // 释放这个 tcp_stream 的所有监听者
    i = a_tcp->listeners;
    while (i) {
        j = i->next;
        free(i);
        i = j;
    }
    
    // 将这个 tcp_stream 加入空闲链表
    a_tcp->next_free = free_streams;
    free_streams = a_tcp;
    tcp_num--;
}

/*
 检测 nids_tcp_timeouts 链表，将比指定时间 now 创建的更早的 tcp_stream 释放掉
 这个函数是在 nids_pcap_handler 调用的
 即pcap抓包后会第一时间检测 nids_tcp_timeouts 链表
 */
void
tcp_check_timeouts(struct timeval *now)
{
    struct tcp_timeout *to;
    struct tcp_timeout *next;
    struct lurker_node *i;
    
    // 清理比指定时间创建更早的 tcp_stream
    for (to = nids_tcp_timeouts; to; to = next) {
        if (now->tv_sec < to->timeout.tv_sec)
            return;
        to->a_tcp->nids_state = NIDS_TIMED_OUT;
        for (i = to->a_tcp->listeners; i; i = i->next)
            (i->item) (to->a_tcp, &i->data);
        next = to->next;
        nids_free_tcp_stream(to->a_tcp);
    }
}

// 通过指定的 tuple4 计算出 tcp_stream 的hash索引
static int
mk_hash_index(struct tuple4 addr)
{
    int hash=mkhash(addr.saddr, addr.source, addr.daddr, addr.dest);
    return hash % tcp_stream_table_size;
}


// 从tcp 报文中获取 sth ？ TODO: ts 是什么？
static int get_ts(struct tcphdr * this_tcphdr, unsigned int * ts)
{
    int len = 4 * this_tcphdr->th_off;
    unsigned int tmp_ts;
    unsigned char * options = (unsigned char*)(this_tcphdr + 1);
    int ind = 0, ret = 0;
    while (ind <=  len - (int)sizeof (struct tcphdr) - 10 )
        switch (options[ind]) {
            case 0: /* TCPOPT_EOL */
                return ret;
            case 1: /* TCPOPT_NOP */
                ind++;
                continue;
            case 8: /* TCPOPT_TIMESTAMP */
                memcpy((char*)&tmp_ts, options + ind + 2, 4);
                *ts=ntohl(tmp_ts);
                ret = 1;
                /* no break, intentionally */
            default:
                if (options[ind+1] < 2 ) /* "silly option" */
                    return ret;
                ind += options[ind+1];
        }
    
    return ret;
}

// TODO : 获取从 tcp 报文中获取 sth?
static int get_wscale(struct tcphdr * this_tcphdr, unsigned int * ws)
{
    int len = 4 * this_tcphdr->th_off;
    unsigned int tmp_ws;
    unsigned char * options = (unsigned char*)(this_tcphdr + 1);
    int ind = 0, ret = 0;
    *ws=1;
    while (ind <=  len - (int)sizeof (struct tcphdr) - 3 )
        switch (options[ind]) {
            case 0: /* TCPOPT_EOL */
                return ret;
            case 1: /* TCPOPT_NOP */
                ind++;
                continue;
            case 3: /* TCPOPT_WSCALE */
                tmp_ws=options[ind+2];
                if (tmp_ws>14)
                    tmp_ws=14;
                *ws=1<<tmp_ws;
                ret = 1;
                /* no break, intentionally */
            default:
                if (options[ind+1] < 2 ) /* "silly option" */
                    return ret;
                ind += options[ind+1];
        }
    
    return ret;
}



/*
 添加新的tcp stream
 当收到新的 tcp connect 时触发，会同时想hash_table, 双链表中添加这个tcp_stream
 this_tcphdr 指向tcp报文， this_iphdr 指向ip报文
 */

static void
add_new_tcp(struct tcphdr * this_tcphdr, struct ip * this_iphdr)
{
    struct tcp_stream *tolink;
    struct tcp_stream *a_tcp;
    int hash_index;
    struct tuple4 addr;
    
    addr.source = ntohs(this_tcphdr->th_sport); // 从tcp报文中获取src和dst的port
    addr.dest = ntohs(this_tcphdr->th_dport);
    addr.saddr = this_iphdr->ip_src.s_addr; // 从ip报文中获取src和dst的ip
    addr.daddr = this_iphdr->ip_dst.s_addr;
    hash_index = mk_hash_index(addr);
    
    // 监听的tcp链接超过最大值时，将最老的 tcp_stream 设置为超时，并通知其所有 listener，然后释放。
    if (tcp_num > max_stream) {
        struct lurker_node *i;
        int orig_client_state=tcp_oldest->client.state;
        tcp_oldest->nids_state = NIDS_TIMED_OUT;
        for (i = tcp_oldest->listeners; i; i = i->next)
            (i->item) (tcp_oldest, &i->data);
        nids_free_tcp_stream(tcp_oldest);
        
        // TCP_SYN_SENT 意味着这个 tcp_stream 的 client 和 server 正处于建立连接的第一次握手阶段
        // 此时会打印一条告警日志
        if (orig_client_state!=TCP_SYN_SENT)
            nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_TOOMUCH, ugly_iphdr, this_tcphdr);
    }
    
    // 从 free streams 是链表开始取出一个tcp_stream 用以初始化待加入 tcp_stream_table 中的 tcp_stream
    a_tcp = free_streams;
    if (!a_tcp) {
        fprintf(stderr, "gdb me ...\n");
        pause();
    }
    free_streams = a_tcp->next_free;
    
    // 初始化新的 tcp_stream
    tcp_num++;
    tolink = tcp_stream_table[hash_index];
    memset(a_tcp, 0, sizeof(struct tcp_stream));
    a_tcp->hash_index = hash_index;
    a_tcp->addr = addr;
    a_tcp->client.state = TCP_SYN_SENT; // 第一次握手 client 发出 syn
    a_tcp->client.seq = ntohl(this_tcphdr->th_seq) + 1;
    a_tcp->client.first_data_seq = a_tcp->client.seq;
    a_tcp->client.window = ntohs(this_tcphdr->th_win);
    a_tcp->client.ts_on = get_ts(this_tcphdr, &a_tcp->client.curr_ts);
    a_tcp->client.wscale_on = get_wscale(this_tcphdr, &a_tcp->client.wscale);
    a_tcp->server.state = TCP_CLOSE; // 第一次握手，server 还未 ack
    
    // 将新的 tcp_stream 插入到hash_table的表头
    a_tcp->next_node = tolink;
    a_tcp->prev_node = 0;
    if (tolink)
        tolink->prev_node = a_tcp;
    tcp_stream_table[hash_index] = a_tcp;
    
    // 将新的 tcp_stream 插入到时序双链表的latest的一端
    a_tcp->next_time = tcp_latest;
    a_tcp->prev_time = 0;
    if (!tcp_oldest)
        tcp_oldest = a_tcp;
    if (tcp_latest)
        tcp_latest->prev_time = a_tcp;
    tcp_latest = a_tcp;
}

/*
 将新收到的数据包添加到指定的接收者 half_stream 中
 half_stream 的 data 指针会指向所有收到的 data
 这个函数
 */
static void
add2buf(struct half_stream * rcv, char *data, int datalen)
{
    int toalloc;
    
    //
    if (datalen + rcv->count - rcv->offset > rcv->bufsize) {
        
        // 初始分配 2048 或者 datalen * 2
        if (!rcv->data) {
            if (datalen < 2048)
                toalloc = 4096; // 最少分配4096
            else
                toalloc = datalen * 2;
            rcv->data = malloc(toalloc);
            rcv->bufsize = toalloc; // bufsize 是已分配的 data 的大小
        }
        else {
            // 根据 datalen和 bufsize 有不同的再分配策略
            if (datalen < rcv->bufsize)
                toalloc = 2 * rcv->bufsize;
            else
                toalloc = rcv->bufsize + 2*datalen;
            rcv->data = realloc(rcv->data, toalloc);
            rcv->bufsize = toalloc;
        }
        
        // 内存不足时添加附加信息『add2buf』
        if (!rcv->data)
            nids_params.no_mem("add2buf");
    }
    memcpy(rcv->data + rcv->count - rcv->offset, data, datalen);
    rcv->count_new = datalen;
    rcv->count += datalen;
}

/*
 这个函数的功能是根据条件调用这个 tcp_stream 的相关 listener 的 callback 函数
 例如：
    目前通过 nids_register_tcp (tcp_callback) 函数注册了一个 tcp_callback 回调函数
    其核心代码如下：
    void tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed){
        char buf[1024];
        strcpy (buf, adres (a_tcp->addr));
        if (a_tcp->nids_state == NIDS_JUST_EST){
            a_tcp->server.collect_urg++; // 表示监听 urg 标记的报文
            a_tcp->client.collect_urg++; // 同上
        }
        else {
            ...
        }
        ...
    }
 这个 callback 函数通过if条件中的代码会监听urg标记报文，当libnids收到有这种标记的报文时则会通知符合条件的listener，调用其 callback 函数
*/
static void
ride_lurkers(struct tcp_stream * a_tcp, char mask)
{
    struct lurker_node *i;
    char cc, sc, ccu, scu;
    
    // 依次调用查看所有 listener 是否需要调用 callback
    for (i = a_tcp->listeners; i; i = i->next)
        if (i->whatto & mask) {
            cc = a_tcp->client.collect;
            sc = a_tcp->server.collect;
            ccu = a_tcp->client.collect_urg;
            scu = a_tcp->server.collect_urg;
            
            // 对于满足条件的 listener，调用其callback 函数，并更改 whatto 标记
            // 比如上面的例子中会如果符合条件会执行 tcp_callbakc 函数
            (i->item) (a_tcp, &i->data);
            if (cc < a_tcp->client.collect)
                i->whatto |= COLLECT_cc;
            if (ccu < a_tcp->client.collect_urg)
                i->whatto |= COLLECT_ccu;
            if (sc < a_tcp->server.collect)
                i->whatto |= COLLECT_sc;
            if (scu < a_tcp->server.collect_urg)
                i->whatto |= COLLECT_scu;
            if (cc > a_tcp->client.collect)
                i->whatto &= ~COLLECT_cc;
            if (ccu > a_tcp->client.collect_urg)
                i->whatto &= ~COLLECT_ccu;
            if (sc > a_tcp->server.collect)
                i->whatto &= ~COLLECT_sc;
            if (scu > a_tcp->server.collect_urg)
                i->whatto &= ~COLLECT_scu;
        }
}

/*
 报文接收者 rcv（是一个half_stream）根据收到的 tcp_stream 进行下一步操作
 判断触发哪一种类型的 ride_lurkers
 */
static void
notify(struct tcp_stream * a_tcp, struct half_stream * rcv)
{
    struct lurker_node *i, **prev_addr;
    char mask;
    
    // 处理新的 urg 报文
    if (rcv->count_new_urg) {
        if (!rcv->collect_urg)
            return;
        if (rcv == &a_tcp->client)
            mask = COLLECT_ccu;
        else
            mask = COLLECT_scu;
        ride_lurkers(a_tcp, mask);
        goto prune_listeners;
    }
    
    // 处理新的报文，仅当设置过 rcv->collect 时
    if (rcv->collect) {
        if (rcv == &a_tcp->client)
            mask = COLLECT_cc;
        else
            mask = COLLECT_sc;
        do {
            int total;
            a_tcp->read = rcv->count - rcv->offset;
            total=a_tcp->read; // 得到新数据的长度
            
            ride_lurkers(a_tcp, mask);
            
            // listener 处理完 tcp_stream 后，仍然有一部分待处理的 data 没有被处理
            // 更新 count_new 使其等于剩余 data 的长度
            if (a_tcp->read>total-rcv->count_new)

                rcv->count_new=total-a_tcp->read;
            
            // 移动 mem 中的数据
            if (a_tcp->read > 0) {
                memmove(rcv->data, rcv->data + a_tcp->read, rcv->count - rcv->offset - a_tcp->read);
                rcv->offset += a_tcp->read;
            }
        }while (nids_params.one_loop_less && a_tcp->read>0 && rcv->count_new);
        // we know that if one_loop_less!=0, we have only one callback to notify
        rcv->count_new=0; // 处理后将 rcv 的 count_new 置为0
    }
// 判断是否有 listener 需要释放
prune_listeners:
    prev_addr = &a_tcp->listeners;
    i = a_tcp->listeners;
    while (i)
        if (!i->whatto) {
            *prev_addr = i->next;
            free(i);
            i = *prev_addr;
        }
        else {
            prev_addr = &i->next;
            i = i->next;
        }
}


/*
 从skb中读取报文并根据报文类型（紧急、普通）调用 notify 函数，通知 rcv 是否要处理这个报文
 整个报文可以分为三段：
    urg_ptr 之前的有效数据部分，urg_ptr部分，urg_ptr之后的有效数据部分
 */
static void
add_from_skb(struct tcp_stream * a_tcp, struct half_stream * rcv,
             struct half_stream * snd,
             u_char *data, int datalen,
             u_int this_seq, char fin, char urg, u_int urg_ptr)
{
    // lost 是待处理的报文中需要抛弃的长度
    u_int lost = EXP_SEQ - this_seq;
    
    // 报文中
    int to_copy, to_copy2;
    
    // "预"处理符合条件的紧急报文
    // 条件：（1）这是一个紧急报文（2）紧急报文指针在 EXP_SEQ 之后 ？？（3）紧急报文未处理或 rcv 的紧急报文大于当前紧急报文
    // "预"处理：（1）更新 rcv 指针 （2）更新 rcv 的 urg_seen
    if (urg && after(urg_ptr, EXP_SEQ - 1) &&
        (!rcv->urg_seen || after(urg_ptr, rcv->urg_ptr))) {
        rcv->urg_ptr = urg_ptr;// 更新 rcv 的 紧急报文指针位置
        rcv->urg_seen = 1; // 更新标志，表示这个紧急报文已经发现
    }
    
    // 处理满足条件的紧急报文
    // 条件：（1）标记为已发现（2）rcv 的紧急报文指针地址位于丢弃的那部分报文地址之后 （3）rcv 紧急报文指针地址位于新报文的地址之前
    if (rcv->urg_seen && after(rcv->urg_ptr + 1, this_seq + lost) &&
        before(rcv->urg_ptr, this_seq + datalen)) {
        
        // 计算需要添加到 rcv 的紧急报文之前那部分数据(是普通报文数据)
        to_copy = rcv->urg_ptr - (this_seq + lost);
        if (to_copy > 0) {
            // 如果订阅了正常报文 调用 add2buf 把紧急指针之前的内容添加到 rcv 半连接中
            // 并调用 notify 处理正常报文
            if (rcv->collect) {
                add2buf(rcv, (char *)(data + lost), to_copy);
                notify(a_tcp, rcv);
            }
            // 未订阅时则制作一个标记，不调用 notify 处理这些 data
            else {
                
                rcv->count += to_copy;
                rcv->offset = rcv->count; /* clear the buffer */
            }
        }
        
        // 处理紧急报文那部分数据
        rcv->urgdata = data[rcv->urg_ptr - this_seq];
        rcv->count_new_urg = 1; // 标记有新的紧急报文
        notify(a_tcp, rcv);
        rcv->count_new_urg = 0; // 处理完后重置相关紧急报文标示
        rcv->urg_seen = 0;
        rcv->urg_count++;
        
        // 处理紧急报文之后的那部分数据（是普通报文数据）
        to_copy2 = this_seq + datalen - rcv->urg_ptr - 1;
        if (to_copy2 > 0) {
            if (rcv->collect) {
                // 原理同上，不同在于处理紧急报文之后的数据
                add2buf(rcv, (char *)(data + lost + to_copy + 1), to_copy2);
                notify(a_tcp, rcv);
            }
            else {
                rcv->count += to_copy2;
                rcv->offset = rcv->count; /* clear the buffer */
            }
        }
    }
    // 处理普通报文
    else {
        if (datalen - lost > 0) {
            if (rcv->collect) {
                add2buf(rcv, (char *)(data + lost), datalen - lost);
                notify(a_tcp, rcv);
            }
            else {
                rcv->count += datalen - lost;
                rcv->offset = rcv->count; /* clear the buffer */
            }
        }
    }
    // 如果 client 端状态为 FIN_SENT，则将 tcp_stream 移动到超市双链表中
    // 注意： 这里没有做关闭连接的处理，例如从 hash_table 中移除这样的操作
    if (fin) {
        snd->state = FIN_SENT;
        if (rcv->state == TCP_CLOSING)
            add_tcp_closing_timeout(a_tcp);
    }
}

/*
 处理捕获到的 tcp 报文，将报文数据更新到接收者 rcv，并通知其处理报文
 */
static void
tcp_queue(struct tcp_stream * a_tcp, struct tcphdr * this_tcphdr,
          struct half_stream * snd, struct half_stream * rcv,
          char *data, int datalen, int skblen
          )
{
    u_int this_seq = ntohl(this_tcphdr->th_seq);
    struct skbuff *pakiet, *tmp;
    
    /*
     * Did we get anything new to ack?
     */
    
    // 接收到的新报文不是期待接收的报文，意味着接收到一个旧的报文
    // 此时可能有两种情况（1）这个旧报文已经完全处理（2）这个旧报文已经处理了一部分
    // 通过报文的长度、地址和 EXP_SEQ 比较可以计算出
    if (!after(this_seq, EXP_SEQ)) {
        // 这时，触发情况（2），旧报文有一部分数据未处理
        if (after(this_seq + datalen + (this_tcphdr->th_flags & TH_FIN), EXP_SEQ)) {
            /* the packet straddles our window end */
            // 处理这些报文
            get_ts(this_tcphdr, &snd->curr_ts);
            add_from_skb(a_tcp, rcv, snd, (u_char *)data, datalen, this_seq,
                         (this_tcphdr->th_flags & TH_FIN),
                         (this_tcphdr->th_flags & TH_URG),
                         ntohs(this_tcphdr->th_urp) + this_seq - 1);
            /*
             * Do we have any old packets to ack that the above
             * made visible? (Go forward from skb)
             */
            
            // 遍历 rcv 中存储的所有 data（ 在rcv->list 中）并处理其中未处理的部分
            pakiet = rcv->list;
            while (pakiet) {
                // 新报文
                if (after(pakiet->seq, EXP_SEQ))
                    break;
                
                // 旧报文中有未处理的部分
                if (after(pakiet->seq + pakiet->len + pakiet->fin, EXP_SEQ)) {
                    add_from_skb(a_tcp, rcv, snd, pakiet->data,
                                 pakiet->len, pakiet->seq, pakiet->fin, pakiet->urg,
                                 pakiet->urg_ptr + pakiet->seq - 1);
                }
                
                // 清除处理过的数据包
                rcv->rmem_alloc -= pakiet->truesize;
                if (pakiet->prev)
                    pakiet->prev->next = pakiet->next;
                else
                    rcv->list = pakiet->next;
                if (pakiet->next)
                    pakiet->next->prev = pakiet->prev;
                else
                    rcv->listtail = pakiet->prev;
                tmp = pakiet->next;
                free(pakiet->data);
                free(pakiet);
                pakiet = tmp;
            }
        }
        else
            // 情况 1，无需处理
            return;
    }
    // 此时，接收到的是一个全新的数据包
    // 会创建一个 skbuff 实例存储这个数据包
    // 并将指向这个 skbuff 的指针连接到接收者
    else {
        struct skbuff *p = rcv->listtail; // 获取此时链表尾部
        
        pakiet = mknew(struct skbuff);
        pakiet->truesize = skblen;
        rcv->rmem_alloc += pakiet->truesize;
        pakiet->len = datalen;
        pakiet->data = malloc(datalen);
        if (!pakiet->data)
            nids_params.no_mem("tcp_queue");
        memcpy(pakiet->data, data, datalen);
        pakiet->fin = (this_tcphdr->th_flags & TH_FIN);
        /* Some Cisco - at least - hardware accept to close a TCP connection
         * even though packets were lost before the first TCP FIN packet and
         * never retransmitted; this violates RFC 793, but since it really
         * happens, it has to be dealt with... The idea is to introduce a 10s
         * timeout after TCP FIN packets were sent by both sides so that
         * corresponding libnids resources can be released instead of waiting
         * for retransmissions which will never happen.  -- Sebastien Raveau
         */
        if (pakiet->fin) {
            snd->state = TCP_CLOSING;
            if (rcv->state == FIN_SENT || rcv->state == FIN_CONFIRMED)
                add_tcp_closing_timeout(a_tcp);
        }
        pakiet->seq = this_seq;
        pakiet->urg = (this_tcphdr->th_flags & TH_URG);
        pakiet->urg_ptr = ntohs(this_tcphdr->th_urp);
        for (;;) {
            if (!p || !after(p->seq, this_seq))
                break;
            p = p->prev;
        }
        if (!p) {
            // rcv 数据链为空，pakiet置于表头
            pakiet->prev = 0;
            pakiet->next = rcv->list;
            if (rcv->list)
                rcv->list->prev = pakiet;
            rcv->list = pakiet;
            if (!rcv->listtail)
                rcv->listtail = pakiet;
        }
        else {
            // 将 pakiet 置于 p 之后
            pakiet->next = p->next;
            p->next = pakiet;
            pakiet->prev = p;
            if (pakiet->next)
                pakiet->next->prev = pakiet;
            else
                rcv->listtail = pakiet;
        }
    }
}

static void
prune_queue(struct half_stream * rcv, struct tcphdr * this_tcphdr)
{
    struct skbuff *tmp, *p = rcv->list;
    
    nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_BIGQUEUE, ugly_iphdr, this_tcphdr);
    while (p) {
        free(p->data);
        tmp = p->next;
        free(p);
        p = tmp;
    }
    rcv->list = rcv->listtail = 0;
    rcv->rmem_alloc = 0;
}

static void
handle_ack(struct half_stream * snd, u_int acknum)
{
    int ackdiff;
    
    ackdiff = acknum - snd->ack_seq;
    if (ackdiff > 0) {
        snd->ack_seq = acknum;
    }
}
#if 0
static void
check_flags(struct ip * iph, struct tcphdr * th)
{
    u_char flag = *(((u_char *) th) + 13);
    if (flag & 0x40 || flag & 0x80)
        nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_BADFLAGS, iph, th);
    //ECN is really the only cause of these warnings...
}
#endif

struct tcp_stream *
find_stream(struct tcphdr * this_tcphdr, struct ip * this_iphdr,
            int *from_client)
{
    struct tuple4 this_addr, reversed;
    struct tcp_stream *a_tcp;
    
    this_addr.source = ntohs(this_tcphdr->th_sport);
    this_addr.dest = ntohs(this_tcphdr->th_dport);
    this_addr.saddr = this_iphdr->ip_src.s_addr;
    this_addr.daddr = this_iphdr->ip_dst.s_addr;
    a_tcp = nids_find_tcp_stream(&this_addr);
    if (a_tcp) {
        *from_client = 1;
        return a_tcp;
    }
    reversed.source = ntohs(this_tcphdr->th_dport);
    reversed.dest = ntohs(this_tcphdr->th_sport);
    reversed.saddr = this_iphdr->ip_dst.s_addr;
    reversed.daddr = this_iphdr->ip_src.s_addr;
    a_tcp = nids_find_tcp_stream(&reversed);
    if (a_tcp) {
        *from_client = 0;
        return a_tcp;
    }
    return 0;
}

struct tcp_stream *
nids_find_tcp_stream(struct tuple4 *addr)
{
    int hash_index;
    struct tcp_stream *a_tcp;
    
    hash_index = mk_hash_index(*addr);
    for (a_tcp = tcp_stream_table[hash_index];
         a_tcp && memcmp(&a_tcp->addr, addr, sizeof (struct tuple4));
         a_tcp = a_tcp->next_node);
    return a_tcp ? a_tcp : 0;
}


void tcp_exit(void)
{
    int i;
    struct lurker_node *j;
    struct tcp_stream *a_tcp, *t_tcp;
    
    if (!tcp_stream_table || !streams_pool)
        return;
    for (i = 0; i < tcp_stream_table_size; i++) {
        a_tcp = tcp_stream_table[i];
        while(a_tcp) {
            t_tcp = a_tcp;
            a_tcp = a_tcp->next_node;
            for (j = t_tcp->listeners; j; j = j->next) {
                t_tcp->nids_state = NIDS_EXITING;
                (j->item)(t_tcp, &j->data);
            }
            nids_free_tcp_stream(t_tcp);
        }
    }
    free(tcp_stream_table);
    tcp_stream_table = NULL;
    free(streams_pool);
    streams_pool = NULL;
    /* FIXME: anything else we should free? */
    /* yes plz.. */
    tcp_latest = tcp_oldest = NULL;
    tcp_num = 0;
}

void
process_tcp(u_char * data, int skblen)
{
    struct ip *this_iphdr = (struct ip *)data;
    struct tcphdr *this_tcphdr = (struct tcphdr *)(data + 4 * this_iphdr->ip_hl);
    int datalen, iplen;
    int from_client = 1;
    unsigned int tmp_ts;
    struct tcp_stream *a_tcp;
    struct half_stream *snd, *rcv;
    
    ugly_iphdr = this_iphdr;
    iplen = ntohs(this_iphdr->ip_len);
    if ((unsigned)iplen < 4 * this_iphdr->ip_hl + sizeof(struct tcphdr)) {
        nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
                           this_tcphdr);
        return;
    } // ktos sie bawi
    
    datalen = iplen - 4 * this_iphdr->ip_hl - 4 * this_tcphdr->th_off;
    
    if (datalen < 0) {
        nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
                           this_tcphdr);
        return;
    } // ktos sie bawi
    
    if ((this_iphdr->ip_src.s_addr | this_iphdr->ip_dst.s_addr) == 0) {
        nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
                           this_tcphdr);
        return;
    }
    if (!(this_tcphdr->th_flags & TH_ACK))
        detect_scan(this_iphdr);
    if (!nids_params.n_tcp_streams) return;
    if (my_tcp_check(this_tcphdr, iplen - 4 * this_iphdr->ip_hl,
                     this_iphdr->ip_src.s_addr, this_iphdr->ip_dst.s_addr)) {
        nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
                           this_tcphdr);
        return;
    }
#if 0
    check_flags(this_iphdr, this_tcphdr);
    //ECN
#endif
    if (!(a_tcp = find_stream(this_tcphdr, this_iphdr, &from_client))) {
        if ((this_tcphdr->th_flags & TH_SYN) &&
            !(this_tcphdr->th_flags & TH_ACK) &&
            !(this_tcphdr->th_flags & TH_RST))
            add_new_tcp(this_tcphdr, this_iphdr);
        return;
    }
    if (from_client) {
        snd = &a_tcp->client;
        rcv = &a_tcp->server;
    }
    else {
        rcv = &a_tcp->client;
        snd = &a_tcp->server;
    }
    if ((this_tcphdr->th_flags & TH_SYN)) {
        if (from_client || a_tcp->client.state != TCP_SYN_SENT ||
            a_tcp->server.state != TCP_CLOSE || !(this_tcphdr->th_flags & TH_ACK))
            return;
        if (a_tcp->client.seq != ntohl(this_tcphdr->th_ack))
            return;
        a_tcp->server.state = TCP_SYN_RECV;
        a_tcp->server.seq = ntohl(this_tcphdr->th_seq) + 1;
        a_tcp->server.first_data_seq = a_tcp->server.seq;
        a_tcp->server.ack_seq = ntohl(this_tcphdr->th_ack);
        a_tcp->server.window = ntohs(this_tcphdr->th_win);
        if (a_tcp->client.ts_on) {
            a_tcp->server.ts_on = get_ts(this_tcphdr, &a_tcp->server.curr_ts);
            if (!a_tcp->server.ts_on)
                a_tcp->client.ts_on = 0;
        } else a_tcp->server.ts_on = 0;
        if (a_tcp->client.wscale_on) {
            a_tcp->server.wscale_on = get_wscale(this_tcphdr, &a_tcp->server.wscale);
            if (!a_tcp->server.wscale_on) {
                a_tcp->client.wscale_on = 0;
                a_tcp->client.wscale  = 1;
                a_tcp->server.wscale = 1;
            }
        } else {
            a_tcp->server.wscale_on = 0;
            a_tcp->server.wscale = 1;
        }
        return;
    }
    if (
        ! (  !datalen && ntohl(this_tcphdr->th_seq) == rcv->ack_seq  )
        &&
        ( !before(ntohl(this_tcphdr->th_seq), rcv->ack_seq + rcv->window*rcv->wscale) ||
         before(ntohl(this_tcphdr->th_seq) + datalen, rcv->ack_seq)
         )
        )
        return;
    
    if ((this_tcphdr->th_flags & TH_RST)) {
        if (a_tcp->nids_state == NIDS_DATA) {
            struct lurker_node *i;
            
            a_tcp->nids_state = NIDS_RESET;
            for (i = a_tcp->listeners; i; i = i->next)
                (i->item) (a_tcp, &i->data);
        }
        nids_free_tcp_stream(a_tcp);
        return;
    }
    
    /* PAWS check */
    if (rcv->ts_on && get_ts(this_tcphdr, &tmp_ts) &&
        before(tmp_ts, snd->curr_ts))
        return;
    
    if ((this_tcphdr->th_flags & TH_ACK)) {
        if (from_client && a_tcp->client.state == TCP_SYN_SENT &&
            a_tcp->server.state == TCP_SYN_RECV) {
            if (ntohl(this_tcphdr->th_ack) == a_tcp->server.seq) {
                a_tcp->client.state = TCP_ESTABLISHED;
                a_tcp->client.ack_seq = ntohl(this_tcphdr->th_ack);
                {
                    struct proc_node *i;
                    struct lurker_node *j;
                    void *data;
                    
                    a_tcp->server.state = TCP_ESTABLISHED;
                    a_tcp->nids_state = NIDS_JUST_EST;
                    for (i = tcp_procs; i; i = i->next) {
                        char whatto = 0;
                        char cc = a_tcp->client.collect;
                        char sc = a_tcp->server.collect;
                        char ccu = a_tcp->client.collect_urg;
                        char scu = a_tcp->server.collect_urg;
                        
                        (i->item) (a_tcp, &data);
                        if (cc < a_tcp->client.collect)
                            whatto |= COLLECT_cc;
                        if (ccu < a_tcp->client.collect_urg)
                            whatto |= COLLECT_ccu;
                        if (sc < a_tcp->server.collect)
                            whatto |= COLLECT_sc;
                        if (scu < a_tcp->server.collect_urg)
                            whatto |= COLLECT_scu;
                        if (nids_params.one_loop_less) {
                            if (a_tcp->client.collect >=2) {
                                a_tcp->client.collect=cc;
                                whatto&=~COLLECT_cc;
                            }
                            if (a_tcp->server.collect >=2 ) {
                                a_tcp->server.collect=sc;
                                whatto&=~COLLECT_sc;
                            }
                        }
                        if (whatto) {
                            j = mknew(struct lurker_node);
                            j->item = i->item;
                            j->data = data;
                            j->whatto = whatto;
                            j->next = a_tcp->listeners;
                            a_tcp->listeners = j;
                        }
                    }
                    if (!a_tcp->listeners) {
                        nids_free_tcp_stream(a_tcp);
                        return;
                    }
                    a_tcp->nids_state = NIDS_DATA;
                }
            }
            // return;
        }
    }
    if ((this_tcphdr->th_flags & TH_ACK)) {
        handle_ack(snd, ntohl(this_tcphdr->th_ack));
        if (rcv->state == FIN_SENT)
            rcv->state = FIN_CONFIRMED;
        if (rcv->state == FIN_CONFIRMED && snd->state == FIN_CONFIRMED) {
            struct lurker_node *i;
            
            a_tcp->nids_state = NIDS_CLOSE;
            for (i = a_tcp->listeners; i; i = i->next)
                (i->item) (a_tcp, &i->data);
            nids_free_tcp_stream(a_tcp);
            return;
        }
    }
    if (datalen + (this_tcphdr->th_flags & TH_FIN) > 0)
        tcp_queue(a_tcp, this_tcphdr, snd, rcv,
                  (char *) (this_tcphdr) + 4 * this_tcphdr->th_off,
                  datalen, skblen);
    snd->window = ntohs(this_tcphdr->th_win);
    if (rcv->rmem_alloc > 65535)
        prune_queue(rcv, this_tcphdr);
    if (!a_tcp->listeners)
        nids_free_tcp_stream(a_tcp);
}

void
nids_discard(struct tcp_stream * a_tcp, int num)
{
    if (num < a_tcp->read)
        a_tcp->read = num;
}

void
nids_register_tcp(void (*x))
{
    register_callback(&tcp_procs, x);
}

void
nids_unregister_tcp(void (*x))
{
    unregister_callback(&tcp_procs, x);
}

int
tcp_init(int size)
{
    int i;
    struct tcp_timeout *tmp;
    
    if (!size) return 0;
    tcp_stream_table_size = size;
    tcp_stream_table = calloc(tcp_stream_table_size, sizeof(char *));
    if (!tcp_stream_table) {
        nids_params.no_mem("tcp_init");
        return -1;
    }
    max_stream = 3 * tcp_stream_table_size / 4;
    streams_pool = (struct tcp_stream *) malloc((max_stream + 1) * sizeof(struct tcp_stream));
    if (!streams_pool) {
        nids_params.no_mem("tcp_init");
        return -1;
    }
    for (i = 0; i < max_stream; i++)
        streams_pool[i].next_free = &(streams_pool[i + 1]);
    streams_pool[max_stream].next_free = 0;
    free_streams = streams_pool;
    init_hash();
    while (nids_tcp_timeouts) {
        tmp = nids_tcp_timeouts->next;
        free(nids_tcp_timeouts);
        nids_tcp_timeouts = tmp;
    }
    return 0;
}

#if HAVE_ICMPHDR
#define STRUCT_ICMP struct icmphdr
#define ICMP_CODE   code
#define ICMP_TYPE   type
#else
#define STRUCT_ICMP struct icmp
#define ICMP_CODE   icmp_code
#define ICMP_TYPE   icmp_type
#endif

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH ICMP_UNREACH
#define ICMP_PROT_UNREACH ICMP_UNREACH_PROTOCOL
#define ICMP_PORT_UNREACH ICMP_UNREACH_PORT
#define NR_ICMP_UNREACH   ICMP_MAXTYPE
#endif


void
process_icmp(u_char * data)
{
    struct ip *iph = (struct ip *) data;
    struct ip *orig_ip;
    STRUCT_ICMP *pkt;
    struct tcphdr *th;
    struct half_stream *hlf;
    int match_addr;
    struct tcp_stream *a_tcp;
    struct lurker_node *i;
    
    int from_client;
    /* we will use unsigned, to suppress warning; we must be careful with
     possible wrap when substracting
     the following is ok, as the ip header has already been sanitized */
    unsigned int len = ntohs(iph->ip_len) - (iph->ip_hl << 2);
    
    if (len < sizeof(STRUCT_ICMP))
        return;
    pkt = (STRUCT_ICMP *) (data + (iph->ip_hl << 2));
    if (ip_compute_csum((char *) pkt, len))
        return;
    if (pkt->ICMP_TYPE != ICMP_DEST_UNREACH)
        return;
    /* ok due to check 7 lines above */
    len -= sizeof(STRUCT_ICMP);
    // sizeof(struct icmp) is not what we want here
    
    if (len < sizeof(struct ip))
        return;
    
    orig_ip = (struct ip *) (((char *) pkt) + 8);
    if (len < (unsigned)(orig_ip->ip_hl << 2) + 8)
        return;
    /* subtraction ok due to the check above */
    len -= orig_ip->ip_hl << 2;
    if ((pkt->ICMP_CODE & 15) == ICMP_PROT_UNREACH ||
        (pkt->ICMP_CODE & 15) == ICMP_PORT_UNREACH)
        match_addr = 1;
    else
        match_addr = 0;
    if (pkt->ICMP_CODE > NR_ICMP_UNREACH)
        return;
    if (match_addr && (iph->ip_src.s_addr != orig_ip->ip_dst.s_addr))
        return;
    if (orig_ip->ip_p != IPPROTO_TCP)
        return;
    th = (struct tcphdr *) (((char *) orig_ip) + (orig_ip->ip_hl << 2));
    if (!(a_tcp = find_stream(th, orig_ip, &from_client)))
        return;
    if (a_tcp->addr.dest == iph->ip_dst.s_addr)
        hlf = &a_tcp->server;
    else
        hlf = &a_tcp->client;
    if (hlf->state != TCP_SYN_SENT && hlf->state != TCP_SYN_RECV)
        return;
    a_tcp->nids_state = NIDS_RESET;
    for (i = a_tcp->listeners; i; i = i->next)
        (i->item) (a_tcp, &i->data);
    nids_free_tcp_stream(a_tcp);
}

