//
// Created by vidahaha on 2018/6/24.
//

#define HAVE_REMOTE

#include <stdio.h>
#include <stdlib.h>
#include "pcap.h"
#include "pthread.h"
#include <windows.h>
#include "protocol.h"

typedef struct _argument {
    pcap_t *handle;
    int timeLen;
}argument;

void *thread_clock(void *argv) {
    pcap_t *handle = ((argument*)argv)->handle;
    int timeLen = ((argument*)argv)->timeLen;  // set time
    Sleep(timeLen * 1000);
    pcap_breakloop(handle);
}

/* 将数字类型的IP地址转换成字符串类型的 */
#define IPTOSBUFFERS    12
void iptos(u_long in, u_short sport, u_long out, u_short dport)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p, *q;
    p = (u_char *)&in;
    q = (u_char *)&out;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n\n", p[0], p[1], p[2], p[3], sport, q[0], q[1], q[2], q[3], dport);
}

int main(int argc, char const *argv[]) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i = 0;
    pcap_t *adhandle;
    struct pcap_pkthdr *header;    //接收到的数据包的头部
    const u_char *pkt_data;           //接收到的数据包的内容
    int res;                                    //表示是否接收到了数据包
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;                       //过滤时用的子网掩码
    char packet_filter[] = "ip and udp";        //过滤字符
    struct bpf_program fcode;                     //pcap_compile所调用的结构体
    ip_header *ih;                                    //ip头部
    udp_header *uh;                             //udp头部
    u_int ip_len;                                       //ip地址有效长度
    u_short sport,dport;                        //主机字节序列
    ip_address ipAddress;                       // ip地址


    //获取本地机器设备列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL , &alldevs, errbuf) == -1){
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

    for(d= alldevs; d != NULL; d= d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0){
        //没找到设备接口，确认WinPcap已安装，程序退出
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);

    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* 跳转到选中的适配器 */
    for(d=alldevs, i=0; i< inum-1 ; d=d->next, i++);

    /* 打开设备 */
    if ( (adhandle = pcap_open(d->name,          // 设备名
                              65535,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                              1000,             // 读取超时时间
                              NULL,             // 远程机器验证
                              errbuf            // 错误缓冲池
    ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    //所在网络为无线局域网
    if(pcap_datalink(adhandle) ==DLT_IEEE802){
        printf("DLT_IEEE802");
    }
    //所在网络为以太网,Ethernet (10Mb, 100Mb, 1000Mb, and up)
    if(pcap_datalink(adhandle) == DLT_EN10MB){
        printf("DLT_EN10MB");
    }

    //所在网络不是以太网,此处只取这种情况
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        //释放列表
        pcap_freealldevs(alldevs);
        return -1;
    }

    //先获得地址的子网掩码
    if(d->addresses != NULL)
        /* 获得接口第一个地址的掩码 */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* 如果接口没有地址，那么我们假设一个C类的掩码 */
        netmask=0xffffff;

    if(pcap_compile(adhandle,        //适配器处理对象
                    &fcode,
                    packet_filter,   //过滤ip和UDP
                    1,               //优化标志
                    netmask          //子网掩码
    ) < 0) {
        //过滤出现问题
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        // 释放设备列表
        pcap_freealldevs(alldevs);
        return -1;
    }

    //设置过滤器
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    // 打开文件来存放pcap数据包
    pcap_dumper_t *dumpfile;
    dumpfile = pcap_dump_open(adhandle, "./traffic.pcap");
    if(dumpfile == NULL){
        printf("\nError opening output file\n");
        return 0;
    }

    // 开放一个线程去计时，时间到了停止抓包
    pthread_t ptClock;
    argument args;
    args.handle = adhandle;
    int argv_time = atoi(argv[1]);
    args.timeLen = (argv_time > 0) ? argv_time : 10;
    printf("\ncatch_time: %d s\n", args.timeLen);
    if(pthread_create(&ptClock, NULL, thread_clock, &args))
    {
        printf("pthread_create(): Error!\n");
        return -1;
    }

    //利用pcap_next_ex来接受数据包
    while((res = pcap_next_ex(adhandle,&header,&pkt_data))>=0)
    {
        if(res == 0){
            //返回值为0代表接受数据包超时，重新循环继续接收
            continue;
        }else{
            //运行到此处代表接受到正常数据包
            // 保存到文件中
            pcap_dump((u_char *) dumpfile, header, pkt_data);

            // 将时间戳转换成可识别的格式
            struct tm *ltime;
            char timestr[16];
            time_t local_tv_sec;
            local_tv_sec = header->ts.tv_sec;
            ltime=localtime(&local_tv_sec);
            strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

            printf("time: %s len:%d ", timestr, header->len);

            // 获得IP数据包头部的位置
            ih = (ip_header *) (pkt_data +14);    //14为以太网帧头部长度
            //获得UDP头部的位置
            ip_len = (ih->ver_ihl & 0xf) *4;
            printf("ip_length:%d \n",ip_len);
            uh = (udp_header *)((u_char *)ih+ip_len);

            /* 打印IP地址和UDP端口 */
            iptos(ih->saddr, uh->uh_dport, ih->daddr, uh->uh_dport);
        }

    }

    // close all handle
    pcap_dump_close(dumpfile);
    pcap_close(adhandle);
    printf("\nDone!\n");
    return 0;
}