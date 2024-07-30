#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include<stdlib.h>
#include<stdio.h>
#include "ikcp.h"

//#define LINUX



#define LOG_TAG "System.out"
#ifdef LINUX
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <error.h>
#define LOGD(fmt) printf(fmt)
#else
#include <android/log.h>
#define LOGD(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define Printf(fmt, ...)LOGD(fmt, ## __VA_ARGS__)
#endif
#define USERUDP 0

/*
错误码
-2 链接认证失败
-3 发送失败
-4 接收超时
1 成功
2 用户名密码错误
3 接收失败
4 获取服务器失败
5 kcp链接错误
-5 没有找到IP
*/
static int Errorflag = -1;
static int stoplogin;
static char virtuallp[16];
static char virtualgw[16];
static char gUser[50];
static char gpasswd[50];
static unsigned int getlittleOnline = 0xffffffff;
static char guuid[50];

static char *LJ_strtok(char **cache, char *str, const char *delimit) {
    char *ret = NULL;
    if (delimit == NULL)
        return str;
    if (str != NULL)
        *cache = str;
    if (*cache == NULL)
        return NULL;
    if (strlen(*cache) == 0)
        return NULL;
    ret = *cache;
    char *p = strstr(*cache, delimit);
    if (p != NULL) {
        *cache = p + strlen(delimit);
        unsigned int i;
        for (i = 0; i < strlen(delimit); i++) {
            *(p + i) = '\0';
        }
    } else {
        *cache = NULL;
    }
    return ret;
}

static pthread_mutex_t gProxyServerLock;
unsigned int randomCertification;
struct CheakServer {
    char ip[16];
    int port;
};
static unsigned int Proxyserver;
static unsigned short ProxyserverPort;

static void InitProxyServer(char *ip, unsigned short port) {
    ProxyserverPort = port;
    Proxyserver = inet_addr(ip);
}

#include <arpa/inet.h>

//选择权重
static int gStopCheakProxyServer = 0;
static int UDPCapacity = 1;
static int TCPCapacity = 1;
static int UserCapacity = 1;
static int TimeCapacity = 1;

static void LoadBalancing2to0(void *arg) {
    struct CheakServer *tmp = (struct CheakServer *) arg;
    unsigned char sendBuf[104];
    struct sockaddr_in peeraddr;
    int peer_len = sizeof(peeraddr);
    memset(sendBuf, 0, sizeof(sendBuf));
    sendBuf[0] = 0xff;
    sendBuf[1] = 0xcc;
    sendBuf[2] = 0xcc;
    sendBuf[3] = 0xff;
    sendBuf[4] = 0x01;

    sendBuf[5] = (unsigned char) (randomCertification % 0x100);
    sendBuf[6] = (unsigned char) (randomCertification / 0x100 % 0x100);
    sendBuf[7] = (unsigned char) (randomCertification / 0x10000 % 0x100);
    sendBuf[8] = (unsigned char) (randomCertification / 0x1000000);
    //printf("%.2x %.2x %.2x %.2x\n", sendBuf[5], sendBuf[6], sendBuf[7], sendBuf[8]);
    sendBuf[9] = (unsigned char) (strlen(gUser));
    memcpy(&sendBuf[10], gUser, (unsigned int) (sendBuf[9]));
    sendBuf[(unsigned int) (sendBuf[9]) + 10] = (unsigned char) (strlen(gpasswd));
    memcpy(&sendBuf[(unsigned int) (sendBuf[9]) + 11], gpasswd, strlen(gpasswd));
    int sizesend = strlen(gpasswd) + strlen(gUser) + 11;
    sendBuf[sizesend++] = 0xaa;
    sendBuf[sizesend++] = 0xaa;

    struct timeval starttime;
    struct timeval endtime;
    unsigned char recvbuff[50];
    struct sockaddr_in sockAddr;
    sockAddr.sin_family = PF_INET;
    sockAddr.sin_addr.s_addr = inet_addr(tmp->ip);
    sockAddr.sin_port = htons(tmp->port + 1);
    int serversoc = socket(AF_INET, SOCK_DGRAM, 0);


    struct timeval timeout;
    timeout.tv_sec = 5;//秒
    timeout.tv_usec = 0;//微秒
    setsockopt(serversoc, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));


    gettimeofday(&starttime, NULL);

    int n = 0;
    for (size_t i = 0; i < 5; i++) {
        sendto(serversoc, (char *) sendBuf, sizesend, 0, (struct sockaddr *) &sockAddr,
               sizeof(struct sockaddr_in));

        gettimeofday(&starttime, NULL);
        n = recvfrom(serversoc, (char *) recvbuff, sizeof(recvbuff), 0,
                     (struct sockaddr *) &peeraddr, (socklen_t *) &peer_len);
        if (n < 0) {
            pthread_mutex_lock(&gProxyServerLock);
            if (gStopCheakProxyServer != 0) {
                pthread_mutex_unlock(&gProxyServerLock);
                close(serversoc);
                free(tmp);
                return;
            }
            pthread_mutex_unlock(&gProxyServerLock);
            continue;
        }
        break;
    }
    if (n < 0) {
        close(serversoc);
        return;
    }
    if (n != 42) {
        //printf("error n %d\n", n);
        close(serversoc);
        return;
    }
    //  printf("recv ok\n");
    gettimeofday(&endtime, NULL);
    unsigned int UDPOnlineNumber =
            recvbuff[0] * 0x1000000 + recvbuff[1] * 0x10000 + recvbuff[2] * 0x100 + recvbuff[3];
    unsigned int TCPOnlineNumber =
            recvbuff[4] * 0x1000000 + recvbuff[5] * 0x10000 + recvbuff[6] * 0x100 + recvbuff[7];
    unsigned int OnlineNumber =
            recvbuff[8] * 0x1000000 + recvbuff[9] * 0x10000 + recvbuff[10] * 0x100 + recvbuff[11];
    unsigned char CPUNumber = recvbuff[12];
    //unsigned int EthUpspeed = recvbuff[13] * 0x1000000 + recvbuff[14] * 0x10000 + recvbuff[15] * 0x100 + recvbuff[16];
    //unsigned int EthDownspeed = recvbuff[17] * 0x1000000 + recvbuff[18] * 0x10000 + recvbuff[19] * 0x100 + recvbuff[20];
    //unsigned int systemtime = recvbuff[38] * 0x1000000 + recvbuff[39] * 0x10000 + recvbuff[40] * 0x100 + recvbuff[41];

    printf("Online=%d CPU=%d\n", OnlineNumber, CPUNumber);
    if (CPUNumber > 90) {
        close(serversoc);
        free(tmp);
        return;
    }
    unsigned int ServerCapacity = (UDPOnlineNumber * (unsigned int) (UDPCapacity) +
                                   TCPOnlineNumber * (unsigned int) (TCPCapacity) +
                                   OnlineNumber * (unsigned int) (UserCapacity) +
                                   (unsigned int) (endtime.tv_usec / 1000 + endtime.tv_sec * 1000 -
                                                   (starttime.tv_usec / 1000 +
                                                    starttime.tv_sec * 1000)) *
                                   (unsigned int) (TimeCapacity));
    pthread_mutex_lock(&gProxyServerLock);
    if (gStopCheakProxyServer != 0) {
        pthread_mutex_unlock(&gProxyServerLock);
        close(serversoc);
        free(tmp);
        return;
    }
    //printf("ServerCapacity=====%d %d\n",ServerCapacity, getlittleOnline);
    if (ServerCapacity < getlittleOnline) {
        getlittleOnline = ServerCapacity;
        InitProxyServer(tmp->ip, tmp->port);
        pthread_mutex_unlock(&gProxyServerLock);
        close(serversoc);
        free(tmp);
        return;
    }
    pthread_mutex_unlock(&gProxyServerLock);
    close(serversoc);
    free(tmp);
    return;
}

static void SplitServer(char *server1) {
    char *server = strdup(server1);
    getlittleOnline = 0xffffffff;
    gStopCheakProxyServer = 0;
    pthread_mutex_init(&gProxyServerLock, NULL);
    char *p;
    char *strcache;
    p = LJ_strtok(&strcache, server, ",");
    while (p) {
        int len = strlen(p);
        if ((len < 10) || (len > 21)) {
            break;
        }
        struct CheakServer *cheakserver = (struct CheakServer *) malloc(sizeof(struct CheakServer));
        if (cheakserver == NULL) {
            break;
        }
        memset(cheakserver, 0, sizeof(struct CheakServer));
        sscanf(p, "%[0-9,.]:%d", cheakserver->ip, &cheakserver->port);
        printf("find %s:%d\n", cheakserver->ip, cheakserver->port);
        pthread_t ntid;
        pthread_create(&ntid, NULL, (void *) LoadBalancing2to0, cheakserver);
        pthread_detach(ntid);
        p = LJ_strtok(&strcache, NULL, ",");
    }
    for (size_t i = 0; i < 5; i++) {
        sleep(1);
        pthread_mutex_lock(&gProxyServerLock);
        if (getlittleOnline != 0xffffffff) {
            gStopCheakProxyServer = 1;
            Errorflag = 0;
            pthread_mutex_unlock(&gProxyServerLock);
            break;
        }
        pthread_mutex_unlock(&gProxyServerLock);
        Errorflag = -6;
    }
    free(server);
    //printf("OK SplitServer\n");
    return;
}

static int CheakUserFlag = -1;
static int CheakUserInfo2to0flag = 0;

static int cheaksleep(int inttime) {
    int i = 0;
    for (i = 0; i < inttime; i++) {
        if (CheakUserInfo2to0flag == 1) {
            CheakUserInfo2to0flag = 0;
            return 1;
        }
        sleep(1);
    }
    return 0;
}

static void CheakUserInfo2to0(void *arg) {
    //CheakUdpUserInfo(NULL);
    struct sockaddr_in sockAddr;
    unsigned char sendBuf[150];
    unsigned char readBuf[150];
    memset(sendBuf, 0, sizeof(sendBuf));
    sendBuf[0] = (unsigned char) (randomCertification % 0x100);
    sendBuf[1] = (unsigned char) (randomCertification / 0x100 % 0x100);
    sendBuf[2] = (unsigned char) (randomCertification / 0x10000 % 0x100);
    sendBuf[3] = (unsigned char) (randomCertification / 0x1000000);

    sendBuf[4] = (unsigned char) (strlen(gUser));
    memcpy(&sendBuf[5], gUser, (unsigned int) (sendBuf[4]));

    sendBuf[(unsigned int) (sendBuf[4]) + 5] = (unsigned char) (strlen(gpasswd));
    memcpy(&sendBuf[(unsigned int) (sendBuf[4]) + 6], gpasswd, strlen(gpasswd));
    int sizesend = strlen(gpasswd) + strlen(gUser) + 6;
    sendBuf[sizesend++] = strlen(guuid);
    memcpy(&sendBuf[sizesend], guuid, strlen(guuid));
    sizesend += strlen(guuid);
    sendBuf[sizesend++] = 0xab;
    sendBuf[sizesend++] = 0xab;
    sockAddr.sin_family = PF_INET;
    sockAddr.sin_addr.s_addr = Proxyserver;
    sockAddr.sin_port = htons(ProxyserverPort);
    struct timeval timeout;
    timeout.tv_sec = 5;//秒
    timeout.tv_usec = 0;//微秒

    for (;;) {
        int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            printf("error socket\n");
            continue;
        }
        if (connect(sock, (struct sockaddr *) &sockAddr, sizeof(struct sockaddr_in)) < 0) {
            CheakUserFlag = 1;
            printf("连接失败 %d.%d.%d.%d:%d\n", (unsigned char) (Proxyserver % 0x100),
                   (unsigned char) (Proxyserver / 0x100 % 0x100),
                   (unsigned char) (Proxyserver / 0x10000 % 0x100),
                   (unsigned char) (Proxyserver / 0x1000000 % 0x100), ProxyserverPort);
            close(sock);
            if (cheaksleep(1) == 1) {
                return;
            }
            continue;
        }
        NETXT:
        if (send(sock, (char *) sendBuf, sizesend, 0) < 0) {
            CheakUserFlag = 2;
            close(sock);
            if (cheaksleep(1) == 1) {
                return;
            }
            continue;
        }
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        int n = recv(sock, (char *) readBuf, 100, 0);
        if (n < 0) {
            CheakUserFlag = 3;
            close(sock);
            if (cheaksleep(1) == 1) {
                return;
            }
            continue;
        }
        readBuf[n] = 0;
        if (n >= 3 && readBuf[0] == 'o' && readBuf[1] == 'k' && readBuf[2] == '|') {
            unsigned int aip = inet_addr((const char *) &readBuf[3]);
            /*int aip = atoi((const char *)&readBuf[3]);*/
            if (aip == 0) {
                CheakUserFlag = 7;
                printf("没有获取到IP(%s)[%d]\n", &readBuf[3], aip);
                close(sock);
                if (cheaksleep(1) == 1) {
                    return;
                }
                continue;
            }
            CheakUserFlag = 4;
            sprintf(virtuallp, "%d.%d.%d.%d", (aip % 0x100), (aip / 0x100 % 0x100),
                    (aip / 0x10000 % 0x100), (aip / 0x1000000 % 0x100));
            sprintf(virtualgw, "%d.%d.%d.1", (aip % 0x100), (aip / 0x100 % 0x100),
                    (aip / 0x10000 % 0x100));
            if (cheaksleep(60 * 2) == 1) {
                return;
            }
            goto NETXT;
        }
        if (strcmp((char *) readBuf, "ok") == 0) {
            CheakUserFlag = 4;
            if (cheaksleep(60 * 2) == 1) {
                return;
            }
            goto NETXT;
        } else if (strcmp((char *) readBuf, "error") == 0) {
            close(sock);
            CheakUserFlag = 5;
            if (cheaksleep(60) == 1) {
                return;
            }
            continue;
        } else {
            CheakUserFlag = 6;
            close(sock);
            if (cheaksleep(60) == 1) {
                return;
            }
            continue;
        }
    }

}

struct VPNMySocket {
    char name[8];
    pthread_mutex_t lock;
    int fd;
    struct sockaddr_in sockAddr;
    ikcpcb *kcp;
};
typedef void *VPNLJFD;
#if USERUDP
static int udphandle;
static struct sockaddr_in udpsockAddr;
#else
static VPNLJFD kcphandle;
#endif
static int udp_output(const char *buf, int len, ikcpcb *kcp, void *user) {
    struct VPNMySocket *fb = (struct VPNMySocket *) user;
    int sendnumb = sendto(fb->fd, buf, len, 0, (struct sockaddr *) &(fb->sockAddr),
                          sizeof(fb->sockAddr));
    if (sendnumb > 1200) {
        printf("sendto %d\n", sendnumb);
    }
    return 0;
}

/* get system time */
static inline void itimeofday(long *sec, long *usec) {
    struct timeval time;
    gettimeofday(&time, NULL);
    if (sec) *sec = time.tv_sec;
    if (usec) *usec = time.tv_usec;
}

/* get clock in millisecond 64 */
static inline IINT64 iclock64(void) {
    long s, u;
    IINT64 value;
    itimeofday(&s, &u);
    value = ((IINT64) s) * 1000 + (u / 1000);
    return value;
}

static inline unsigned int iclock() {
    return (unsigned int) (iclock64() & 0xfffffffful);
}

static int InitupdateFlushflag = 0;
static int vpnhandle = 0;

static void InitupdateFlush(void *arg) {
    struct VPNMySocket *fb = (struct VPNMySocket *) arg;
    unsigned int numn = 0;
    char buff[5];
    memset(buff, 0, sizeof(buff));
    for (;;) {
        usleep(1000);
        if (InitupdateFlushflag == 1) {
            InitupdateFlushflag = 0;
            return;
        }
        pthread_mutex_lock(&((struct VPNMySocket *) fb)->lock);
        ikcp_update(((struct VPNMySocket *) fb)->kcp, iclock());
        numn++;
        //printf("ok:%d\n",numn);
        if (numn > 1000 * 100) {
            numn = 0;
            printf("ikcp_send\n");
            ikcp_send(((struct VPNMySocket *) fb)->kcp, buff, sizeof(buff));
        }
        pthread_mutex_unlock(&((struct VPNMySocket *) fb)->lock);
#if 0
        pthread_mutex_lock(&((struct VPNMySocket *) fb)->lock);
        int ret = ikcp_recv(((struct VPNMySocket *) fb)->kcp, (char *) buff, sizeof(buff));
        if (vpnhandle != 0){
            if(ret>0){
                printf("write to %d\n",ret);
                int writesize=write(vpnhandle, buff, ret);
            }
        }
        pthread_mutex_unlock(&((struct VPNMySocket *) fb)->lock);
#endif
    }
    return;
}


static int ReaddateFlushFlushflag = 0;

static void ReaddateFlush(void *arg) {
#if USERUDP
    socklen_t len;
    char buff[1500];
    struct sockaddr_in clent_addr;
    int ret;
    for (;;) {
        if (ReaddateFlushFlushflag == 1) {
            ReaddateFlushFlushflag = 0;
            return;
        }
        ret = recvfrom(udphandle, buff, sizeof(buff), 0, (struct sockaddr*)&clent_addr, &len);
        if((vpnhandle != 0)&&(ret>0))
            write(vpnhandle, buff, ret);
    }
#else
    struct VPNMySocket *fb = (struct VPNMySocket *) arg;
    char buff[1500];
    struct sockaddr_in cli_addr;
    int cli_addr_len, n, ret;
    memset(buff, 0, sizeof(buff));
    int flags = fcntl(((struct VPNMySocket *) fb)->fd, F_GETFL, 0);
    // fcntl(((struct VPNMySocket *) fb)->fd, F_SETFL, flags & O_NONBLOCK);
    fcntl(((struct VPNMySocket *) fb)->fd, F_SETFL, flags | O_NONBLOCK);
    for (;;) {
        if (ReaddateFlushFlushflag == 1) {
            ReaddateFlushFlushflag = 0;
            return;
        }
        n = recvfrom(((struct VPNMySocket *) fb)->fd, buff, sizeof(buff), 0,
                     (struct sockaddr *) &cli_addr, &cli_addr_len);
        //printf("接收=%d\n", n);
        pthread_mutex_lock(&((struct VPNMySocket *) fb)->lock);
        if (n > 0)
            ikcp_input(((struct VPNMySocket *) fb)->kcp, buff, n);
        ret = ikcp_recv(((struct VPNMySocket *) fb)->kcp, (char *) buff, sizeof(buff));
        if (vpnhandle != 0) {
            if (ret > 0) {
                printf("write to %d\n", ret);
                int writesize = write(vpnhandle, buff, ret);
            }
        }
        pthread_mutex_unlock(&((struct VPNMySocket *) fb)->lock);
        usleep(1000 * 10);
    }
#endif
    return;
}



#if 0
static void ReaddateFlush2(void *arg) {
    struct VPNMySocket *fb = (struct VPNMySocket *) arg;
    char buff[1500];
    struct sockaddr_in cli_addr;
    int cli_addr_len, n, ret;
    memset(buff, 0, sizeof(buff));
    for (;;) {
        if (ReaddateFlushFlushflag == 1) {
            ReaddateFlushFlushflag = 0;
            return;
        }
        /*n = recvfrom(((struct VPNMySocket *) fb)->fd, buff, sizeof(buff), 0,
                     (struct sockaddr *) &cli_addr, &cli_addr_len);*/
        /*if (n <= 0) {
            printf("接收=%d\n", n);
            continue;
        }*/
        usleep(1000*10);
        pthread_mutex_lock(&((struct VPNMySocket *) fb)->lock);
            ret = ikcp_recv(((struct VPNMySocket *) fb)->kcp, (char *) buff, sizeof(buff));
            if (vpnhandle != 0){
                if(ret>0){
                    printf("write to %d\n",ret);
                    int writesize=write(vpnhandle, buff, ret);
                }
            }
        pthread_mutex_unlock(&((struct VPNMySocket *) fb)->lock);
    }
    return;
}
#endif

static VPNLJFD
NineVPNCreatFlowTrack(unsigned int ssid, unsigned int ip, unsigned short port, int minrto) {
    struct VPNMySocket *fb = (struct VPNMySocket *) malloc(sizeof(struct VPNMySocket));
    srand(time(NULL));
    for (size_t i = 0; i < 5; i++) {
        ssid += (unsigned int) rand();
    }
    pthread_mutex_init(&fb->lock, NULL);
    fb->fd = socket(AF_INET, SOCK_DGRAM, 0);
    //设置为非阻塞模式
    //int imode = 0;
    //ioctlsocket(fb->fd, FIONBIO, (u_long *)&imode);
    strcpy(fb->name, "client");
    fb->sockAddr.sin_family = PF_INET;
    fb->sockAddr.sin_addr.s_addr = ip; //inet_addr(ip);
    fb->sockAddr.sin_port = htons(port);
    printf("handle=%d\n", ssid);
    fb->kcp = ikcp_create(ssid, (void *) fb);
    fb->kcp->output = udp_output;
    //ikcp_wndsize(fb->kcp, 10, 1);
    ikcp_nodelay(fb->kcp, 1, 10, 1, 1);
    ikcp_wndsize(fb->kcp, 1024, 1024);
    fb->kcp->rx_minrto = minrto;
    //fb->kcp->dead_link = 1;//重传次数
    pthread_t ntid;
    pthread_create(&ntid, NULL, (void *) InitupdateFlush, fb);
    pthread_detach(ntid);
    pthread_create(&ntid, NULL, (void *) ReaddateFlush, fb);
    pthread_detach(ntid);
    //pthread_create(&ntid, NULL, (void *) ReaddateFlush2, fb);
    // pthread_detach(ntid);
    ikcp_send(((struct VPNMySocket *) fb)->kcp, "123", 3);
    return (void *) fb;
}

typedef struct {
    int Errorflag;
    char Virtuallp[16];
    char Virtualgw[16];
} INITIP;

/*
初始化ninevpn
user 用户名
passwd 密码
uuid 机器唯一ID
platform 运行平台
servers 服务器地址（支持多服务器自动选择格式如下：192.168.2.3:4000,192.168.2.3:6000）
返回值
错误码
-2 链接认证失败
-3 发送失败
-4 接收超时
1 成功
2 用户名密码错误
3 接收失败
4 获取服务器失败
5 kcp链接错误
-5 没有找到IP
Virtuallp 本机要配置的虚拟IP
Virtualgw 本机要配置的虚拟网关
*/

INITIP InitNineVPN(char *user, char *passwd, char *uuid, char *platform, char *servers) {
    srand((unsigned int) time(NULL));
    stoplogin = 1;
    Errorflag = 0;
    CheakUserFlag = -1;
    getlittleOnline = 0xffffffff;
    strcpy(gUser, user);
    strcpy(gpasswd, passwd);
    sprintf(guuid, "%s%s\n", platform, uuid);
    randomCertification = rand();
    SplitServer(servers);
  //  SplitServer("58.218.200.201:2000");
    INITIP gtmp;
    if (Errorflag != 0) {
        gtmp.Errorflag = Errorflag;
        return gtmp;
    }
    pthread_t ntid;
    pthread_create(&ntid, NULL, (void *) CheakUserInfo2to0, NULL);
    pthread_detach(ntid);
    int runflag = 0;
    while (CheakUserFlag == -1) {
        runflag++;
        if (runflag > 10) {
            gtmp.Errorflag = -4;
            return gtmp;
        }
        sleep(1);
    }
    if (CheakUserFlag != 4) {
        gtmp.Errorflag = CheakUserFlag;
        return gtmp;
    }
    gtmp.Errorflag = 1;
    strcpy(gtmp.Virtuallp, virtuallp);
    strcpy(gtmp.Virtualgw, virtualgw);
#if USERUDP
    udphandle= socket(AF_INET, SOCK_DGRAM, 0);
    //设置为非阻塞模式
    //int imode = 0;
    //ioctlsocket(fb->fd, FIONBIO, (u_long *)&imode);
    udpsockAddr.sin_family = PF_INET;
    udpsockAddr.sin_addr.s_addr = Proxyserver; //inet_addr(ip);
    udpsockAddr.sin_port = htons(ProxyserverPort+2);
    pthread_create(&ntid, NULL, (void *) ReaddateFlush, NULL);
    pthread_detach(ntid);
#else
    kcphandle = NineVPNCreatFlowTrack(randomCertification, Proxyserver, ProxyserverPort, 30);
#endif
    printf("成功 ip=%s  gw=%s\n", gtmp.Virtuallp, gtmp.Virtualgw);
    return gtmp;
}

/*
设置判断权重
(cpu权重不用设置 cpu使用超过90%自动停用)
UserWeights 在线用户权重
timeWeights 查找时间权重
*/
void WeightsChange(int UserWeights, int timeWeights) {
    UserCapacity = UserWeights;
    TimeCapacity = timeWeights;
}

/*
发送数据包
pack 发送数据包
packlen 要发送数据长度
返回
	发送的字节数
*/
int Sendpack(unsigned char *pack, int packlen) {

#if USERUDP
    if (pack[0]  != 0x45) {
        return packlen;
    }
    int ret = sendto(udphandle, pack, packlen, 0, (struct sockaddr*)&udpsockAddr, sizeof(udpsockAddr));
#else
    // if ((pack[0] & 0x40) != 0x40) {
    //     return packlen;
    // }
   pthread_mutex_lock(&((struct VPNMySocket *) kcphandle)->lock);
    if (((struct VPNMySocket *) kcphandle)->kcp->state == 0xffffffff) {
        printf("close\n");
    }
    int ret = ikcp_send(((struct VPNMySocket *) kcphandle)->kcp, (char *) pack, packlen);
    ikcp_flush(((struct VPNMySocket *) kcphandle)->kcp);
    pthread_mutex_unlock(&((struct VPNMySocket *) kcphandle)->lock);
#endif
    return ret;
}

/*
接收数据
pack 接收数据包缓存
packlen 缓存大小
返回
	接收的字节数
*/
int Readpack(unsigned char *pack, int packlen) {
#if USERUDP
    socklen_t len;
    struct sockaddr_in clent_addr;
    int ret = recvfrom(udphandle, pack, packlen, 0, (struct sockaddr*)&clent_addr, &len);
#else
    pthread_mutex_lock(&((struct VPNMySocket *) kcphandle)->lock);
    int ret = ikcp_recv(((struct VPNMySocket *) kcphandle)->kcp, (char *) pack, packlen);
    pthread_mutex_unlock(&((struct VPNMySocket *) kcphandle)->lock);
#endif
    return ret;
}

#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<unistd.h>
#include<stdlib.h>
#include<errno.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<string.h>
#include<signal.h>
#include <fcntl.h>

/*
关闭通信
*/
void CloseNineVPN() {
    LOGD("开始关闭\n");
#if USERUDP
    CheakUserInfo2to0flag = 1;
    Errorflag = -1;
    stoplogin = 1;
    vpnhandle = 0;
    close(udphandle);
    while (CheakUserInfo2to0flag == 1)
        sleep(1);

#else
    vpnhandle = 0;
    Errorflag = -1;
    stoplogin = 1;
    CheakUserInfo2to0flag = 1;
    InitupdateFlushflag = 1;
    ReaddateFlushFlushflag = 1;
    fcntl(((struct VPNMySocket *) kcphandle)->fd, F_GETFL, O_NONBLOCK);
    close(((struct VPNMySocket *) kcphandle)->fd);
    LOGD("等待关闭\n");
    while (ReaddateFlushFlushflag == 1)
        sleep(1);
    LOGD("等待关闭成功\n");
    memset(virtuallp, 0, sizeof(virtuallp));
    memset(virtualgw, 0, sizeof(virtualgw));
    memset(guuid, 0, sizeof(guuid));
    getlittleOnline = 0xffffffff;
    pthread_mutex_destroy(&((struct VPNMySocket *) kcphandle)->lock);
    while (CheakUserInfo2to0flag == 1)
        sleep(1);
    while (InitupdateFlushflag == 1)
        sleep(1);
    ikcp_release(((struct VPNMySocket *) kcphandle)->kcp);
    pthread_mutex_destroy(&gProxyServerLock);
    free(kcphandle);
#endif
}


static void InitSendpack(void *arg) {
    int n = 0;
    unsigned char buff[1500];
    for (;;) {
        if (vpnhandle == 0) {
            sleep(1);
            continue;
        }
        n = read(vpnhandle, buff, sizeof(buff));
        if (n < 0) {
            //usleep(100*1000);
            printf("read error=%d\n", vpnhandle);
            continue;
        }
        if (n > 1200) {
            printf("read etho %d\n", n);
        }
        Sendpack(buff, n);
    }

}

void InitVPNhand(int handle) {
    printf("句柄来了", handle);
    vpnhandle = handle;
    int flags = fcntl(vpnhandle, F_GETFL, 0);
    fcntl(vpnhandle, F_SETFL, flags & ~O_NONBLOCK);
    static int flagrun = 0;
    if (flagrun == 0) {
        flagrun = 1;
        pthread_t ntid;
        pthread_create(&ntid, NULL, (void *) InitSendpack, NULL);
        pthread_detach(ntid);
    }
}

#ifdef LINUX
int main(){
    int i;
    for(i=0;;i++){
    InitNineVPN("12312313", "eqweqeqe", "sdadadasdsdad", "android", "58.218.200.201:2000");
    unsigned char pack[5];
    Sendpack(pack,sizeof(pack));
    CloseNineVPN();
    printf("run = %d\n",i);
    sleep(2);
    }
    return 0;
}
#endif


