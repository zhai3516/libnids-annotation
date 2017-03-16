/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/

#ifndef _NIDS_NIDS_H
# define _NIDS_NIDS_H

# include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <pcap.h>

# ifdef __cplusplus
extern "C" {
# endif

# define NIDS_MAJOR 1
# define NIDS_MINOR 24

enum
{
  NIDS_WARN_IP = 1,
  NIDS_WARN_TCP,
  NIDS_WARN_UDP,
  NIDS_WARN_SCAN
};

enum
{
  NIDS_WARN_UNDEFINED = 0,
  NIDS_WARN_IP_OVERSIZED,
  NIDS_WARN_IP_INVLIST,
  NIDS_WARN_IP_OVERLAP,
  NIDS_WARN_IP_HDR,
  NIDS_WARN_IP_SRR,
  NIDS_WARN_TCP_TOOMUCH,
  NIDS_WARN_TCP_HDR,
  NIDS_WARN_TCP_BIGQUEUE,
  NIDS_WARN_TCP_BADFLAGS
};

# define NIDS_JUST_EST 1
# define NIDS_DATA 2
# define NIDS_CLOSE 3
# define NIDS_RESET 4
# define NIDS_TIMED_OUT 5
# define NIDS_EXITING   6	/* nids is exiting; last chance to get data */

# define NIDS_DO_CHKSUM  0
# define NIDS_DONT_CHKSUM 1

// 源和目标的 ip、port 四元组
struct tuple4
{
  u_short source; // src port
  u_short dest; // dst port
  u_int saddr; // src ip
  u_int daddr; // dst ip
};

// 一个半连接结构
struct half_stream
{
  char state; // socket 状态，如TCP_SYN_SENT，TCP_ESTABLISHED，TCP_CLOSE等
  char collect; // 标识是否收集正常报文
  char collect_urg; // 标识是否收集紧急报文

  char *data; // 指向一个存储已经ack的tcp正常数据的buffer的指针
  int offset; // 标识新数据在上述buffer中的起始地址
  int count; // 建立连接后，收集到的所有数据的大小(bytes)
  int count_new; // 从上次回调到当前新到达的数据大小(bytes)
  int bufsize; // buffer的实际大小(bytes)

  int urg_count;
  u_int acked;
  u_int seq;
  u_int ack_seq;
  u_int first_data_seq;
  u_char urgdata; // One-byte buffer for urgent data ?
  u_char count_new_urg; // 新收到紧急报文的大小
  u_char urg_seen; // 标识是否发现紧急报文
  u_int urg_ptr; // 紧急报文的起始地址
  u_short window; // tcp 窗口
  u_char ts_on; // 标识是否使用时间戳
  u_char wscale_on; // 标识是否使用wscale ？
  u_int curr_ts;  // 当前时间戳
  u_int wscale; // ?
  struct skbuff *list; // 这个半连接收到的所有tcp报文链表
  struct skbuff *listtail; // 上述链表的尾
  int rmem_alloc; // 已分配给list的内存空间(bytes)

};

// 存储一个tcp链接的相关内容
struct tcp_stream
{
  struct tuple4 addr;
  char nids_state; // libnid 定义的 tcp 状态
  struct lurker_node *listeners;  // 监听这个 tcp 连接的所有callback函数
  struct half_stream client; // client half stream
  struct half_stream server; // server half stream
  struct tcp_stream *next_node;
  struct tcp_stream *prev_node;
  int hash_index; // hash table key 值
  struct tcp_stream *next_time;
  struct tcp_stream *prev_time;
  int read;
  struct tcp_stream *next_free; // 下一个可用的 free tcp stream
  void *user;
};

// libnids对外开发的参数
struct nids_prm
{
  int n_tcp_streams;
  int n_hosts;
  char *device;
  char *filename;
  int sk_buff_size;
  int dev_addon;
  void (*syslog) ();
  int syslog_level;
  int scan_num_hosts;
  int scan_delay;
  int scan_num_ports;
  void (*no_mem) (char *);
  int (*ip_filter) ();
  char *pcap_filter;
  int promisc;
  int one_loop_less;
  int pcap_timeout;
  int multiproc;
  int queue_limit;
  int tcp_workarounds;
  pcap_t *pcap_desc;
};

// 按时间排列的tcp连接双链表
struct tcp_timeout
{
  struct tcp_stream *a_tcp;
  struct timeval timeout;
  struct tcp_timeout *next;
  struct tcp_timeout *prev;
};

int nids_init (void);
void nids_register_ip_frag (void (*));
void nids_unregister_ip_frag (void (*));
void nids_register_ip (void (*));
void nids_unregister_ip (void (*));
void nids_register_tcp (void (*));
void nids_unregister_tcp (void (*x));
void nids_register_udp (void (*));
void nids_unregister_udp (void (*));
void nids_killtcp (struct tcp_stream *);
void nids_discard (struct tcp_stream *, int);
int nids_run (void);
void nids_exit(void);
int nids_getfd (void);
int nids_dispatch (int);
int nids_next (void);
void nids_pcap_handler(u_char *, struct pcap_pkthdr *, u_char *);
struct tcp_stream *nids_find_tcp_stream(struct tuple4 *);
void nids_free_tcp_stream(struct tcp_stream *);

extern struct nids_prm nids_params;
extern char *nids_warnings[];
extern char nids_errbuf[];
extern struct pcap_pkthdr *nids_last_pcap_header;
extern u_char *nids_last_pcap_data;
extern u_int nids_linkoffset;
extern struct tcp_timeout *nids_tcp_timeouts;

struct nids_chksum_ctl {
	u_int netaddr;
	u_int mask;
	u_int action;
	u_int reserved;
};
extern void nids_register_chksum_ctl(struct nids_chksum_ctl *, int);

# ifdef __cplusplus
}
# endif

#endif /* _NIDS_NIDS_H */
