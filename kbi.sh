#!/bin/bash
# Kubernetes Binarization Installer v0.0.4
# Author zhangweilong
set -e
while getopts i OPT;do
# i后面没有冒号表示这是个布尔值的选项，带了这个选项即为真
    case $OPT in    
        i)
            echo -e "\033[32m========================================================================\033[0m"
            echo -e "\033[32mKubernetes Binarization Installer\033[0m"
            echo -e "\033[32m欢迎使用KBI(Kubernetes Binarization Installer)\033[0m"
            echo -e "\033[32m========================================================================\033[0m"
            echo -e "\033[32m请在部署节点执行安装操作，部署节点可以是集群节点中的其中一个,或是任何可以连接至目标K8s集群的节点\033[0m"
            echo -e "\033[32m如果是在云环境，请确保安全组放通VRRP协议（IP协议号112），在OpenStack中，还需要配置Master节点端口的allowed-port-pairs功能\033[0m"
            read -p "输入Master节点IP,以空格分割:" -a MasterIP
            read -p "输入Node节点IP,以空格分割,默认与Master节点相同:" -a NodeIP
            read -p "输入K8s集群VIP:" k8sVIP
            read -p "输入Pod网段,以CIDR格式表示,默认172.23.0.0/16(按回车跳过):" podNet
            read -p "输入Service网段,以CIDR格式表示,默认10.253.0.0/16(按回车跳过):" serviceNet
            read -p "输入Kubernetes版本,默认1.18.10(按回车跳过): " k8sVersion
            read -p "输入docker-ce版本,默认最新版(按回车跳过): " dockerVersion
            ;;
        ?)
	    # TO DO LIST
            ;;
        esac
done

# Master节点数量
mCount=${#MasterIP[@]}
# Node节点数量
nCount=${#NodeIP[@]}
if [ $nCount -eq 0 ];then
    nodeCount=(${MasterIP[@]})
    NodeIP=(${MasterIP[@]})
else
    nodeCount=(${MasterIP[@]} ${NodeIP[@]})
fi
echo "节点总数:${#nodeCount[@]},Master数量:${#MasterIP[@]},Node数量:${#NodeIP[@]}"
echo "Master节点："
for i in ${MasterIP[@]};do echo $i;done
echo "Node节点:"
for i in ${NodeIP[@]};do echo $i;done
echo
if [ -z "$k8sVersion" ];then
    k8sVersion=1.18.10
fi
if [ -z "$podNet" ];then
    podNet=172.23.0.0/16
fi
if [ -z "$serviceNet" ];then
    serviceNet=10.253.0.0/16
fi
firstServiceIP=$(echo $serviceNet | awk -F'/' '{print $1}' | sed 's/0$/1/')
clusterDnsIP=$(echo $serviceNet | awk -F'/' '{print $1}' | sed 's/0$/2/')

if [[ -e /etc/kubernetes/pki/bootstrap/token.csv ]];then
	bootstrapToken=$(awk -F',' '{print $1}' /etc/kubernetes/pki/bootstrap/token.csv)
else
	bootstrapToken=$(head -c 16 /dev/urandom | od -An -t x | tr -d ' ')
fi

autoSSHCopy(){
    echo -e "\033[32m正在配置各节点SSH互信免密登录..........\033[0m"
    if [ ! -e /root/.ssh/id_rsa ];then
        echo "公钥文件不存在"
        ssh-keygen -t rsa -P '' -f /root/.ssh/id_rsa
    fi
    for i in ${nodeCount[@]};do ssh-copy-id $i;done
}



# Preparation
preparation(){
echo -e "\033[32m开始执行部署流程..........\033[0m"
cat << EOF > /etc/yum.repos.d/docker-ce.repo
[docker-ce-stable]
name=Docker CE Stable - $basearch
baseurl=https://mirrors.aliyun.com/docker-ce/linux/centos/7/\$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://mirrors.aliyun.com/docker-ce/linux/centos/gpg
EOF

# 内核参数
cat << EOF  > /etc/sysctl.d/kubernetes.conf
net.core.netdev_max_backlog=10000
net.core.somaxconn=32768
net.ipv4.tcp_max_syn_backlog=8096
fs.inotify.max_user_instances=8192
fs.file-max=2097152
fs.inotify.max_user_watches=524288
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 12582912 16777216
net.ipv4.tcp_wmem=4096 12582912 16777216
net.core.rps_sock_flow_entries=8192
net.ipv4.neigh.default.gc_thresh1=2048
net.ipv4.neigh.default.gc_thresh2=4096
net.ipv4.neigh.default.gc_thresh3=8192
vm.max_map_count=262144
kernel.threads-max=30058
net.ipv4.ip_forward=1
kernel.core_pattern=core
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
vm.swappiness=0
vm.overcommit_memory=1
vm.panic_on_oom=0
fs.inotify.max_user_watches=89100
fs.file-max=52706963
fs.nr_open=52706963
net.ipv6.conf.all.disable_ipv6=1
EOF

# 复制阿里云yum源配置文件和kubernetes.conf内核参数文件并安装依赖包
if [[ ! -e /usr/local/bin/cfssl || ! -e /usr/local/bin/cfssljson ]];then
    yum install wget -y &> /dev/null
    wget https://kuberocker.oss-cn-shenzhen.aliyuncs.com/cfssl/cfssl -O /usr/local/bin/cfssl 
    #
    wget https://kuberocker.oss-cn-shenzhen.aliyuncs.com/cfssl/cfssljson -O /usr/local/bin/cfssljson
    #
fi
chmod a+x /usr/local/bin/*

# 生成CA证书和私钥
if [ ! -d /etc/kubernetes/pki/CA ];then mkdir -p /etc/kubernetes/pki/CA ;fi
echo -e "\033[32m生成CA自签证书和私钥..........\033[0m"
cat << EOF > /etc/kubernetes/pki/CA/ca-config.json
{
    "signing": {
        "default": {
            "expiry": "876000h"
        },
        "profiles": {
            "kubernetes": {
                "expiry": "876000h",
                "usages": [
                    "signing",
                    "key encipherment",
                    "server auth",
                    "client auth"
                ]
            }
        }
    }
} 
EOF
# 这里修改的只是控制平面和kube-proxy的证书过期时间，100年
# kubelet自己的证书有效期默认是一年，修改需要改源码

cat << EOF > /etc/kubernetes/pki/CA/ca-csr.json
{
    "CA": {
        "expiry": "876000h",
        "pathlen": 0
    },
    "CN": "kubernetes",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "GuangDong",
            "L": "GuangZhou",
            "O": "Dolphin",
            "OU": "Ops"
        }
    ]
} 
EOF

cd /etc/kubernetes/pki/CA
if [[ ! -e /etc/kubernetes/pki/CA/ca.pem && ! -e /etc/kubernetes/pki/CA/ca-key.pem ]];then
    cfssl gencert -initca /etc/kubernetes/pki/CA/ca-csr.json | cfssljson -bare ca
fi

# 初始化
for i in ${nodeCount[@]};do
    scp /etc/yum.repos.d/docker-ce.repo root@$i:/etc/yum.repos.d/
    scp /etc/sysctl.d/kubernetes.conf root@$i:/etc/sysctl.d/
    ssh $i "yum install -y curl chrony sysstat conntrack ipvsadm ipset jq iptables psmisc iptables-services libseccomp && modprobe br_netfilter && sysctl -p /etc/sysctl.d/kubernetes.conf && mkdir -p /etc/kubernetes/pki/CA &> /dev/null"
    ssh $i "systemctl mask firewalld ; setenforce 0 ; sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config"
    ssh $i "modprobe br_netfilter ip_vs_rr nf_conntrack nf_conntrack_ipv4 &> /dev/null"
    if [ -z "$dockerVersion" ];then
        ssh $i "yum install docker-ce -y"
    else
        ssh $i "yum install docker-ce-$dockerVersion -y"
    fi
    scp /etc/kubernetes/pki/CA/* $i:/etc/kubernetes/pki/CA
    echo -e "\033[32m节点$i 初始化安装完成\033[0m" 
    echo -e "\033[32m====================\033[0m"
    echo 
done

# iptables，注意这里其实没开，因为很多人的环境不一样，如果加一条reject规则可能影响已存在的环境
echo -e "\033[32m正在为各节点配置iptables规则..........\033[0m"
cat << EOF > /etc/sysconfig/iptables
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 514 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 1080 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 2379 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 2380 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 6443 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 8080 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 8443 -j ACCEPT
-A INPUT -m pkttype --pkt-type multicast -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
COMMIT
EOF
for i in ${nodeCount[@]};do
    scp /etc/sysconfig/iptables $i:/etc/sysconfig/iptables
    ssh $i "systemctl restart iptables"
done

# 配置NTP
# 将以输入的第一个MasterIP作为NTP服务器
echo -e "\033[32m正在配置NTP服务器，服务器地址为${MasterIP[0]}..........\033[0m"
allowNTP=${MasterIP[0]}
netNTP=$(echo $allowNTP | awk -F'.' '{print $1,$2 }' | sed  's/ /./')
cat << EOF > /tmp/chrony.conf
server ntp1.aliyun.com iburst
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
allow ${netNTP}.0.0/16
logdir /var/log/chrony
EOF
cat << EOF > /tmp/chrony.conf_otherNode
server ${MasterIP[0]} iburst
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
EOF
scp /etc/chrony.conf ${MasterIP[0]}:/etc/
ssh ${MasterIP[0]} "systemctl restart chronyd"
echo -e "\033[32mNTP服务器完成..........\033[0m"
}

# 生成Haproxy的配置文件，默认使用MasterIP中的前三个节点
deployHaproxyKeepalived (){
for i in ${MasterIP[@]};do ssh $i "useradd keepalived_script &> /dev/null &";done
for i in ${MasterIP[@]};do ssh $i "echo 'keepalived_script ALL = (root) NOPASSWD:ALL' > /etc/sudoers.d/keepalived_script";done
cat << EOF > /tmp/haproxy.cfg 
global
    log /dev/log    local0
    log /dev/log    local1 notice
    chroot /var/lib/haproxy
    stats socket /var/run/haproxy-admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    nbproc 1

defaults
    log     global
    timeout connect 5000
    timeout client  10m
    timeout server  10m

listen  admin_stats
    bind 0.0.0.0:10080
    mode http
    log 127.0.0.1 local0 err
    stats refresh 30s
    stats uri /status
    stats realm welcome login\ Haproxy
    stats auth admin:DreamCatcher
    stats hide-version
    stats admin if TRUE

listen kube-master
    bind 0.0.0.0:8443
    mode tcp
    option tcplog
    balance source
    server k8s-master1 ${MasterIP[0]}:6443 check inter 2000 fall 2 rise 2 weight 1
    server k8s-master2 ${MasterIP[1]}:6443 check inter 2000 fall 2 rise 2 weight 1
    server k8s-master3 ${MasterIP[2]}:6443 check inter 2000 fall 2 rise 2 weight 1
EOF

# 安装配置Keepalived和Haproxy，并根据节点的不同分别为不同节点的Keepalived设置优先级
weight=1
for i in ${MasterIP[@]};do
((keepalivedPriority=$weight+100))
ssh $i "yum install haproxy keepalived -y && systemctl enable haproxy keepalived"
interfaceName=$(ssh $i "ip a | grep -i $i -B 2 | awk 'NR==1{print \$2}' | sed 's/://'")
cat << EOF > /tmp/keepalived.conf
global_defs {
    router_id k8s-master-$i
}
    
vrrp_script check-haproxy {
    script "sudo killall -0 haproxy"
    interval 5
    weight -30
}
    
vrrp_instance VI-kube-master {
    state MASTER
    priority $keepalivedPriority
    dont_track_primary
    interface $interfaceName
    virtual_router_id 68
    advert_int 3
    track_script {
        check-haproxy
    }
    virtual_ipaddress {
        $k8sVIP   
    }
}
EOF
((weight=$weight+10))
scp /tmp/haproxy.cfg $i:/etc/haproxy/haproxy.cfg
scp /tmp/keepalived.conf $i:/etc/keepalived/
echo -e "\033[32m节点$i 正在启动Haproxy && Keepalived..........\033[0m"
ssh $i "systemctl start haproxy keepalived && systemctl enable haproxy keepalived"
if [ $? ];then
    echo -e "\033[32m节点${i} Haproxy && Keepalived启动完成\033[0m"
else
    echo -e "\033[31m节点${i} Haproxy && Keepalived启动失败，请执行systemctl status keepalived haproxy查看日志\033[0m"
fi
echo 
done
}

deployETCD(){
    echo -e "\033[32m正在部署etcd..........\033[0m"
    if [ ! -d /etc/kubernetes/pki/etcd ];then mkdir -p /etc/kubernetes/pki/etcd/;fi
    cat << EOF > /etc/kubernetes/pki/etcd/etcd-csr.json
    {
        "CN": "etcd",
        "hosts": [
            "127.0.0.1",
            "${MasterIP[0]}",
            "${MasterIP[1]}",
            "${MasterIP[2]}"
        ],
        "key": {
            "algo": "rsa",
            "size": 2048
        },
        "names": [
            {
                "C": "CN",
                "ST": "GuangDong",
                "L": "GuangZhou",
                "O": "Dolphin",
                "OU": "Ops"
            }
        ]
    }
EOF

cd /etc/kubernetes/pki/etcd/
if [[ ! -e /etc/kubernetes/pki/etcd/etcd.pem && ! -e /etc/kubernetes/pki/etcd/etcd-key.pem ]];then
cfssl gencert -ca=/etc/kubernetes/pki/CA/ca.pem \
-ca-key=/etc/kubernetes/pki/CA/ca-key.pem \
-config=/etc/kubernetes/pki/CA/ca-config.json \
-profile=kubernetes etcd-csr.json | cfssljson -bare etcd
fi

if [[ ! -e /tmp/etcd-v3.3.10-linux-amd64.tar.gz ]];then
    wget https://kuberocker.oss-cn-shenzhen.aliyuncs.com/etcd/3.3.10/etcd-v3.3.10-linux-amd64.tar.gz -O /tmp/etcd-v3.3.10-linux-amd64.tar.gz
    tar xvf /tmp/etcd-v3.3.10-linux-amd64.tar.gz -C /tmp
fi

index=0
for i in ${MasterIP[@]};do
if [ ! -d /tmp/etcd/ ];then ssh $i "mkdir /tmp/etcd/" ;fi
cat << EOF > /tmp/etcd/etcd.conf
ETCD_ARGS="--name=etcd-$index \\
  --cert-file=/etc/kubernetes/pki/etcd/etcd.pem \\
  --key-file=/etc/kubernetes/pki/etcd/etcd-key.pem \\
  --peer-cert-file=/etc/kubernetes/pki/etcd/etcd.pem \\
  --peer-key-file=/etc/kubernetes/pki/etcd/etcd-key.pem \\
  --trusted-ca-file=/etc/kubernetes/pki/CA/ca.pem \\
  --peer-trusted-ca-file=/etc/kubernetes/pki/CA/ca.pem \\
  --initial-advertise-peer-urls=https://$i:2380 \\
  --listen-peer-urls=https://0.0.0.0:2380 \\
  --listen-client-urls=https://0.0.0.0:2379 \\
  --advertise-client-urls=https://$i:2379 \\
  --initial-cluster-token=etcd-cluster-1 \\
  --initial-cluster=etcd-0=https://${MasterIP[0]}:2380,etcd-1=https://${MasterIP[1]}:2380,etcd-2=https://${MasterIP[2]}:2380 \\
  --initial-cluster-state=new \\
  --data-dir=/var/lib/etcd"
EOF
cat << EOF > /tmp/etcd/etcd.service
[Unit]
Description=Etcd Server
Documentation=https://github.com/coreos
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
WorkingDirectory=/var/lib/etcd/
EnvironmentFile=/usr/local/etc/etcd.conf
ExecStart=/usr/local/bin/etcd \$ETCD_ARGS
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    if $(ssh $i "[[ -f /etc/systemd/system/etcd.service ]]");then
        echo -e "\033[32m节点$i 已存在ETCD systemd service文件，跳过此步骤..........\033[0m"
    else
        scp /tmp/etcd/etcd.service $i:/etc/systemd/system/ &> /dev/null &
    fi

    if $(ssh $i "systemctl status etcd &> /dev/null");then
        echo -e "\033[32m节点$i ETCD正在运行中，跳过此步骤..........\033[0m"
    else
        scp /tmp/etcd-v3.3.10-linux-amd64/etcd* $i:/usr/local/bin
    fi

    if $(ssh $i "[[ -d /etc/kubernetes/pki/etcd/ ]]");then
        echo -e "\033[32m节点$i 已存在/etc/kubernetes/pki/etcd/目录，跳过此步骤..........\033[0m"
    else
        ssh $i "mkdir -p /etc/kubernetes/pki/etcd/"
    fi

    if $(ssh $i "[[ -d /var/lib/etcd/ ]]");then
        echo -e "\033[32m节点$i 已存在/var/lib/etcd/目录，跳过此步骤..........\033[0m"
    else
        ssh $i "mkdir -p /var/lib/etcd/"
    fi

    if $(ssh $i "[[ -d /var/lib/etcd/ ]]");then
        echo -e "\033[32m节点$i 已存在/var/lib/etcd/目录，跳过此步骤..........\033[0m"
    else
        ssh $i "mkdir -p  /var/lib/etcd/"
    fi

    if $(ssh $i "[[ -f /etc/kubernetes/pki/etcd/etcd-key.pem ]]");then
        echo -e "\033[32m节点$i 已存在ETCD证书私钥文件，跳过此步骤..........\033[0m"
    else
        scp /etc/kubernetes/pki/etcd/* $i:/etc/kubernetes/pki/etcd/ 
    fi

    scp /tmp/etcd/etcd.conf $i:/usr/local/etc/
    let index+=1
    echo 
done

echo -e "\033[32m正在启动etcd.....\033[0m"
ssh ${MasterIP[0]} "systemctl enable etcd && systemctl start etcd " &
sleep 5

for i in ${MasterIP[@]};do
    if [ ! $i = ${MasterIP[0]} ];then
        ssh $i "systemctl enable etcd && systemctl start etcd "
        if [ $? ];then
            echo -e "\033[32m${i} etcd启动成功\033[0m"
        else
            echo -e "\033[31m${i} etcd启动失败，请检查日志\033[0m"
        fi
    fi
done
}

setKubectl(){
    if [[ ! $(which kube-apiserver) ]];then
        wget https://kuberocker.oss-cn-shenzhen.aliyuncs.com/$k8sVersion/kubernetes-server-linux-amd64.tar.gz -O /opt/kubernetes-server-linux-amd64.tar.gz && tar xvf /opt/kubernetes-server-linux-amd64.tar.gz  -C /opt/&& cd /opt/kubernetes/server/bin && rm -rf *.tar *.docker_tag 
        for i in ${nodeCount[@]};do
            scp /opt/kubernetes/server/bin/* $i:/usr/local/bin/ 
            ssh $i "chmod a+x /usr/local/bin/*"
        done
    else
        echo -e "\033[31m已检测到/usr/local/bin/目录下存在kubernetes二进制文件，如果需要重新下载和复制到其他节点上，请删除所有/usr/local/bin/目录下的kubernetes二进制文件，并重新运行工具 v${k8sVersion}二进制文件的步骤\033[0m"
    fi

    if [ ! -d /etc/kubernetes/pki/admin ];then mkdir -p /etc/kubernetes/pki/admin  ;fi
    cd /etc/kubernetes/pki/admin
    cat <<EOF > /etc/kubernetes/pki/admin/admin-csr.json
    {
        "CN": "admin",
        "hosts": [],
        "key": {
            "algo": "rsa",
            "size": 2048
        },
        "names": [
            {
                "C": "CN",
                "ST": "GuangZhou",
                "L": "GuangDong",
                "O": "system:masters",
                "OU": "Ops"
            }
        ]
    }
EOF

if [[ ! -e /etc/kubernetes/pki/admin/admin.pem && ! -e /etc/kubernetes/pki/admin/admin-key.pem ]];then
cfssl gencert -ca=/etc/kubernetes/pki/CA/ca.pem \
-ca-key=/etc/kubernetes/pki/CA/ca-key.pem \
-config=/etc/kubernetes/pki/CA/ca-config.json \
-profile=kubernetes /etc/kubernetes/pki/admin/admin-csr.json | cfssljson -bare admin
fi

kubectl config set-cluster kubernetes \
--certificate-authority=/etc/kubernetes/pki/CA/ca.pem \
--embed-certs=true \
--server=https://${k8sVIP}:8443 \
--kubeconfig=/etc/kubernetes/pki/admin/admin.conf

kubectl config set-credentials admin \
--client-certificate=/etc/kubernetes/pki/admin/admin.pem \
--embed-certs=true \
--client-key=/etc/kubernetes/pki/admin/admin-key.pem \
--kubeconfig=/etc/kubernetes/pki/admin/admin.conf

kubectl config set-context admin@kubernetes \
--cluster=kubernetes \
--user=admin \
--kubeconfig=/etc/kubernetes/pki/admin/admin.conf

kubectl config use-context admin@kubernetes --kubeconfig=/etc/kubernetes/pki/admin/admin.conf

for i in ${MasterIP[@]};do
     ssh $i "mkdir -p /etc/kubernetes/pki/admin /root/.kube/ &"
     scp /etc/kubernetes/pki/admin/admin* $i:/etc/kubernetes/pki/admin/ 2> /dev/null
     scp /etc/kubernetes/pki/admin/admin.conf $i:/root/.kube/config 2> /dev/null
     echo -e "\033[32m${i} kubectl配置完成\033[0m"
    done
}

deployFlannel(){
    mkdir -p /etc/kubernetes/pki/flannel/ 2> /dev/null
    cd /etc/kubernetes/pki/flannel/
    cat << EOF > /etc/kubernetes/pki/flannel/flannel-csr.json
    {
        "CN": "flanneld",
        "hosts": [],
        "key": {
            "algo": "rsa",
            "size": 2048
        },
        "names": [
            {
                "C": "CN",
                "ST": "GuangDong",
                "L": "GuangZhou",
                "O": "Dolphin",
                "OU": "Ops"
            }
        ]
    }
EOF

if [[ ! -e /etc/kubernetes/pki/flannel/flannel.pem && ! -e /etc/kubernetes/pki/flannel/flannel-key.pem ]];then
cfssl gencert -ca=/etc/kubernetes/pki/CA/ca.pem \
-ca-key=/etc/kubernetes/pki/CA/ca-key.pem \
-config=/etc/kubernetes/pki/CA/ca-config.json \
-profile=kubernetes /etc/kubernetes/pki/flannel/flannel-csr.json | cfssljson -bare flannel
fi

etcdctl --endpoints=https://${MasterIP[0]}:2379 \
--ca-file=/etc/kubernetes/pki/CA/ca.pem \
--cert-file=/etc/kubernetes/pki/flannel/flannel.pem \
--key-file=/etc/kubernetes/pki/flannel/flannel-key.pem \
set /kubernetes/network/config  '{"Network":"'${podNet}'", "SubnetLen": 24, "Backend": {"Type": "vxlan"}}'

if [[ ! $(which flanneld) ]];then
   wget https://kuberocker.oss-cn-shenzhen.aliyuncs.com/flannel/0.10.0/flannel-v0.10.0-linux-amd64.tar.gz -O /opt/flannel-v0.10.0-linux-amd64.tar.gz 
   tar xvf /opt/flannel-v0.10.0-linux-amd64.tar.gz -C /opt/
   cp /opt/{flanneld,mk-docker-opts.sh} /usr/local/bin/
fi

cat << EOF > /etc/systemd/system/flanneld.service
[Unit]
Description=Flanneld overlay address etcd agent
Documentation=https://github.com/coreos
After=network.target
After=network-online.target
Wants=network-online.target
After=etcd.service
Before=docker.service

[Service]
Type=notify
EnvironmentFile=/usr/local/etc/flanneld.conf
ExecStart=/usr/local/bin/flanneld \$FLANNELD_ARGS
ExecStartPost=/usr/local/bin/mk-docker-opts.sh -k DOCKER_NETWORK_OPTIONS -d /run/flannel/docker
Restart=on-failure

[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
EOF

cat << EOF > /usr/local/etc/flanneld.conf
FLANNELD_ARGS="-etcd-cafile=/etc/kubernetes/pki/CA/ca.pem \\
  -etcd-certfile=/etc/kubernetes/pki/flannel/flannel.pem \\
  -etcd-keyfile=/etc/kubernetes/pki/flannel/flannel-key.pem \\
  -etcd-endpoints=https://${MasterIP[0]}:2379,https://${MasterIP[1]}:2379,https://${MasterIP[2]}:2379 \\
  -etcd-prefix=/kubernetes/network"
EOF

cat << EOF > /tmp/docker.service
[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
BindsTo=containerd.service
After=network-online.target firewalld.service containerd.service
Wants=network-online.target
Requires=docker.socket
[Service]
Type=notify
EnvironmentFile=-/run/flannel/docker
ExecStart=/usr/bin/dockerd -H fd:// \$DOCKER_NETWORK_OPTIONS --containerd=/run/containerd/containerd.sock
ExecReload=/bin/kill -s HUP $MAINPID
TimeoutSec=0
RestartSec=2
Restart=always
StartLimitBurst=3
StartLimitInterval=60s
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
Delegate=yes
KillMode=process
[Install]
WantedBy=multi-user.target
EOF
for i in ${nodeCount[@]};do

    ssh $i "if [ ! -d /etc/kubernetes/pki/flannel/ ];then mkdir -p /etc/kubernetes/pki/flannel/ /run/flannel ; touch /run/flannel/docker;fi" 

    if $(ssh $i systemctl status flanneld &> /dev/null);then
        echo -e "\033[32m$i Flanneld正在运行中，跳过复制可执行文件步骤..........\033[0m"
    else
        scp /opt/{flanneld,mk-docker-opts.sh} $i:/usr/local/bin/ 
    fi

    if $(ssh $i "[[ -f /etc/kubernetes/pki/flannel/flannel.pem && -f /etc/kubernetes/pki/flannel/flannel-key.pem ]]");then
        echo -e "\033[32m$i 已存在Flanneld证书文件，跳过此步骤..........\033[0m"
    else
        scp /etc/kubernetes/pki/flannel/flannel* $i:/etc/kubernetes/pki/flannel/ 
    fi

    if $(ssh $i "[[ -f /etc/systemd/system/flanneld.service ]]");then
        echo -e "\033[32m$i 已存在Flanneld Systemd Service文件，跳过此步骤..........\033[0m"
    else
        scp /etc/systemd/system/flanneld.service $i:/etc/systemd/system/flanneld.service 
    fi

    scp /usr/local/etc/flanneld.conf $i:/usr/local/etc/flanneld.conf 
    scp /tmp/docker.service $i:/usr/lib/systemd/system/docker.service 
    ssh $i "systemctl daemon-reload ; systemctl enable docker flanneld"
    ssh $i "systemctl daemon-reload && systemctl start flanneld &> /dev/null" 
    ssh $i "systemctl daemon-reload && systemctl start docker &> /dev/null" 
    # ssh $i "systemctl daemon-reload;systemctl enable docker flanneld && systemctl start flanneld ; systemctl restart flanneld && systemctl start docker ;systemctl restart docker"
    if [ $? ];then
        echo -e "\033[32m $i Flanneld 启动成功\033[0m"
    else
        echo -e "\033[31m $i Flanneld 启动失败\033[0m"
    fi
done
}

deployApiserver(){
    if [ -d /etc/kubernetes/pki/apiserver/ ];then 
        echo -e "\033[32m本地已存在/etc/kubernetes/pki/apiserver目录，跳过此步骤..........\033[0m"
    else
        mkdir -p /etc/kubernetes/pki/apiserver/ /etc/kubernetes/pki/bootstrap 
    fi

    if [ -d /etc/kubernetes/pki/bootstrap/ ];then 
        echo -e "\033[32m本地已存在/etc/kubernetes/pki/bootstrap目录，跳过此步骤..........\033[0m"
    else
        mkdir -p /etc/kubernetes/pki/bootstrap 
    fi

if [[ ! -e /etc/kubernetes/pki/bootstrap/token.csv ]];then
    cat << EOF > /etc/kubernetes/pki/bootstrap/token.csv
${bootstrapToken},kubelet-bootstrap,10001,"system:kubelet-bootstrap"
EOF
fi
    cd /etc/kubernetes/pki/apiserver/ 
    cat << EOF > /etc/kubernetes/pki/apiserver/apiserver-csr.json
{
    "CN": "kubernetes",
    "hosts": [
      "127.0.0.1",
      "${firstServiceIP}",
      "kubernetes",
      "kubernetes.default",
      "kubernetes.default.svc",
      "kubernetes.default.svc.cluster",
      "kubernetes.default.svc.cluster.local"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "GuangDong",
            "L": "GuangZhou",
            "O": "Dolphin",
            "OU": "Ops"
        }
    ]
}
EOF

cat << EOF > /etc/systemd/system/kube-apiserver.service
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
User=root
EnvironmentFile=/usr/local/etc/kube-apiserver.conf
ExecStart=/usr/local/bin/kube-apiserver \$KUBE_API_ARGS
Restart=on-failure
RestartSec=5
Type=notify
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    # 遍历所有节点,将所有节点的IP写入到csr.json里面的hosts字段
    # 这里本来可以只写master节点的IP，但考虑到新增apiserver需要重新生成csr文件，所以将用户输入的所有IP都写了进去
    nIndex=0
    nodeCountLen=${#nodeCount[@]}
    while (( nIndex < nodeCountLen ))
    do
       sed -i "4 a\"${nodeCount[$nIndex]}\"," /etc/kubernetes/pki/apiserver/apiserver-csr.json
       sed -i '5s/^/      /' /etc/kubernetes/pki/apiserver/apiserver-csr.json
     let nIndex+=1
    done
    sed -i "4 a\"${k8sVIP}\"," /etc/kubernetes/pki/apiserver/apiserver-csr.json
    sed -i '5s/^/      /' /etc/kubernetes/pki/apiserver/apiserver-csr.json
    if [[ ! -e /etc/kubernetes/pki/apiserver.pem && ! -e /etc/kubernetes/pki/apiserver/apiserver-key.pem ]];then
        cfssl gencert -ca=/etc/kubernetes/pki/CA/ca.pem \
        -ca-key=/etc/kubernetes/pki/CA/ca-key.pem \
        -config=/etc/kubernetes/pki/CA/ca-config.json \
        -profile=kubernetes apiserver-csr.json | cfssljson -bare apiserver    
    fi

for i in ${MasterIP[@]};do
echo > /tmp/kube-apiserver.conf
cat << EOF > /tmp/kube-apiserver.conf
KUBE_API_ARGS="--admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota,NodeRestriction \\
  --advertise-address=$i \\
  --bind-address=0.0.0.0 \\
  --insecure-port=0 \\
  --authorization-mode=Node,RBAC \\
  --runtime-config=rbac.authorization.k8s.io/v1beta1 \\
  --kubelet-https=true \\
  --token-auth-file=/etc/kubernetes/pki/bootstrap/token.csv \\
  --service-cluster-ip-range=${serviceNet} \\
  --service-node-port-range=10000-60000 \\
  --tls-cert-file=/etc/kubernetes/pki/apiserver/apiserver.pem \\
  --tls-private-key-file=/etc/kubernetes/pki/apiserver/apiserver-key.pem \\
  --client-ca-file=/etc/kubernetes/pki/CA/ca.pem \\
  --service-account-key-file=/etc/kubernetes/pki/CA/ca-key.pem \\
  --etcd-cafile=/etc/kubernetes/pki/CA/ca.pem \\
  --etcd-certfile=/etc/kubernetes/pki/apiserver/apiserver.pem \\
  --etcd-keyfile=/etc/kubernetes/pki/apiserver/apiserver-key.pem \\
  --storage-backend=etcd3 \\
  --etcd-servers=https://${MasterIP[0]}:2379,https://${MasterIP[1]}:2379,https://${MasterIP[2]}:2379 \\
  --enable-swagger-ui=true \\
  --allow-privileged=true \\
  --apiserver-count=3 \\
  --audit-log-maxage=30 \\
  --audit-log-maxbackup=3 \\
  --audit-log-maxsize=100 \\
  --audit-log-path=/var/lib/audit.log \\
  --event-ttl=1h \\
  --logtostderr=false \\
  --log-dir=/var/log/kubernetes/apiserver \\
  --v=2"
EOF
    if $(ssh $i "[[ -d /etc/kubernetes/pki/apiserver ]]");then
        echo -e "\033[32m$i 已存在/etc/kubernetes/pki/apiserver目录，跳过此步骤..........\033[0m"
    else
        ssh $i mkdir -p /etc/kubernetes/pki/apiserver/  
    fi
    
    if $(ssh $i "[[ -d /etc/kubernetes/pki/bootstrap ]]");then
        echo -e "\033[32m$i 已存在/etc/kubernetes/pki/bootstrap目录，跳过此步骤..........\033[0m"
    else
        ssh $i mkdir -p /etc/kubernetes/pki/bootstrap
    fi

    if $(ssh $i "[[ -d /var/log/kubernetes/apiserver  ]]");then
        echo -e "\033[32m$i 已存在/var/log/kubernetes/apiserver目录，跳过此步骤..........\033[0m"
    else
        ssh $i mkdir -p /var/log/kubernetes/bootstrap
    fi

    if $(ssh $i "[[ -f /etc/kubernetes/pki/bootstrap/token.csv ]]");then
        echo -e "\033[32m$i 已存在/etc/kubernetes/pki/bootstrap/token.csv文件，跳过此步骤..........\033[0m"
    else
        scp /etc/kubernetes/pki/bootstrap/token.csv $i:/etc/kubernetes/pki/bootstrap/ 
    fi

    if $(ssh $i "[[ -f /etc/kubernetes/pki/apiserver/apiserver-key.pem ]]");then
        echo -e "\033[32m$i 已存在kube-apiserver证书私钥文件，跳过此步骤..........\033[0m"
    else
        scp /etc/kubernetes/pki/apiserver/apiserver* $i:/etc/kubernetes/pki/apiserver/ 
    fi

    if $(ssh $i "[[ -f /etc/systemd/system/kube-apiserver.service ]]");then
        echo -e "\033[32m$i 已存在kube-apiserver service文件，跳过此步骤..........\033[0m"
    else
        scp /etc/systemd/system/kube-apiserver.service $i:/etc/systemd/system/kube-apiserver.service &
    fi

    scp /tmp/kube-apiserver.conf $i:/usr/local/etc/kube-apiserver.conf
    ssh $i "systemctl enable kube-apiserver && systemctl start kube-apiserver"
    if [ $? ];then
        echo -e "\033[32m $i kube-apiserver 启动成功\033[0m"
    else
        echo -e "\033[31m $i kube-apiserver 启动失败，请检查日志文件\033[0m"
    fi
done
}

deployControllerManager(){
    if [ ! -d /etc/kubernetes/pki/controller-manager ];then mkdir -p /etc/kubernetes/pki/controller-manager ;fi
    cd /etc/kubernetes/pki/controller-manager
    cat << EOF > /etc/kubernetes/pki/controller-manager/controller-manager-csr.json
    {
        "CN": "system:kube-controller-manager",
        "hosts": [
          "${MasterIP[0]}",
          "${MasterIP[1]}",
          "${MasterIP[2]}"
        ],
        "key": {
            "algo": "rsa",
            "size": 2048
        },
        "names": [
            {
                "C": "CN",
                "ST": "GuangDong",
                "L": "GuangZhou",
                "O": "system:kube-controller-manager",
                "OU": "Ops"
            }
        ]
    }
EOF
    if [[ ! -e /etc/kubernetes/pki/controller-manager/controller-manager.pem && ! -e /etc/kubernetes/pki/controller-manager/controller-manager-key.pem ]];then
        cfssl gencert -ca=/etc/kubernetes/pki/CA/ca.pem  -ca-key=/etc/kubernetes/pki/CA/ca-key.pem -config=/etc/kubernetes/pki/CA/ca-config.json -profile=kubernetes /etc/kubernetes/pki/controller-manager/controller-manager-csr.json | cfssljson -bare controller-manager
    fi

cat << EOF > /etc/systemd/system/kube-controller-manager.service
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target
After=kube-apiserver.service

[Service]
EnvironmentFile=/usr/local/etc/kube-controller-manager.conf
ExecStart=/usr/local/bin/kube-controller-manager \$KUBE_CONTROLLER_MANAGER_ARGS
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /usr/local/etc/kube-controller-manager.conf
KUBE_CONTROLLER_MANAGER_ARGS="--master=https://${k8sVIP}:8443 \\
  --kubeconfig=/etc/kubernetes/pki/controller-manager/controller-manager.conf \\
  --allocate-node-cidrs=true \\
  --service-cluster-ip-range=${serviceNet} \\
  --cluster-cidr=${podNet} \\
  --cluster-name=kubernetes \\
  --cluster-signing-cert-file=/etc/kubernetes/pki/CA/ca.pem \\
  --cluster-signing-key-file=/etc/kubernetes/pki/CA/ca-key.pem \\
  --service-account-private-key-file=/etc/kubernetes/pki/CA/ca-key.pem \\
  --root-ca-file=/etc/kubernetes/pki/CA/ca.pem \\
  --use-service-account-credentials=true \\
  --controllers=*,bootstrapsigner,tokencleaner \\
  --leader-elect=true \\
  --logtostderr=false \\
  --log-dir=/var/log/kubernetes/controller-manager \\
  --v=2"
EOF

kubectl config set-cluster kubernetes \
--certificate-authority=/etc/kubernetes/pki/CA/ca.pem \
--embed-certs=true \
--server=https://${k8sVIP}:8443 \
--kubeconfig=/etc/kubernetes/pki/controller-manager/controller-manager.conf
kubectl config set-credentials system:kube-controller-manager \
--client-certificate=/etc/kubernetes/pki/controller-manager/controller-manager.pem \
--embed-certs=true \
--client-key=/etc/kubernetes/pki/controller-manager/controller-manager-key.pem \
--kubeconfig=/etc/kubernetes/pki/controller-manager/controller-manager.conf
kubectl config set-context system:kube-controller-manager@kubernetes \
--cluster=kubernetes \
--user=system:kube-controller-manager \
--kubeconfig=/etc/kubernetes/pki/controller-manager/controller-manager.conf
kubectl config use-context system:kube-controller-manager@kubernetes --kubeconfig=/etc/kubernetes/pki/controller-manager/controller-manager.conf

for i in ${MasterIP[@]};do
    if $(ssh $i "[[ -d /etc/kubernetes/pki/controller-manager ]]");then
        echo -e "\033[32m$i 已存在/etc/kubernetes/pki/controller-manager目录,跳过此步骤..........\033[0m"
    else
        ssh $i mkdir -p  /etc/kubernetes/pki/controller-manager
    fi

    if $(ssh $i "[[ -d /var/log/kubernetes/controller-manager/ ]]");then
        echo -e "\033[32m$i 已存在/var/log/kubernetes/controller-manager目录,跳过此步骤..........\033[0m"
    else
        ssh $i mkdir -p  /etc/kubernetes/pki/controller-manager
    fi

    if $(ssh $i "[[ -f /etc/kubernetes/pki/controller-manager/controller-manager-key.pem ]]");then
        echo -e "\033[32m$i 已存在kube-controller-manager证书私钥文件,跳过此步骤..........\033[0m"
    else
        scp /etc/kubernetes/pki/controller-manager/* $i:/etc/kubernetes/pki/controller-manager/ 
    fi

    # if $(ssh $ "[[ -f /etc/kubernetes/pki/controller-manager.conf ]]");then
    #     echo -e "\033[32m$i 已存在kube-controller-manager证书私钥文件,跳过此步骤..........\033[0m"
    # else
    #     scp /usr/local/etc/kube-controller-manager.conf $i:/usr/local/etc/kube-controller-manager.conf &
    # fi

    scp /usr/local/etc/kube-controller-manager.conf $i:/usr/local/etc/kube-controller-manager.conf 

    if $(ssh $i "[[ -f /etc/systemd/system/kube-controller-manager.service ]]");then
        echo -e "\033[32m$i 已存在kube-controller-manager systemd service文件,跳过此步骤..........\033[0m"
    else
        scp /etc/systemd/system/kube-controller-manager.service $i:/etc/systemd/system/kube-controller-manager.service 
    fi

    ssh $i "systemctl enable kube-controller-manager && systemctl start kube-controller-manager"
    if [ $? ];then
        echo -e "\033[32m $i kube-controller-manager 启动成功\033[0m"
    else
        echo -e "\033[31m $i kube-controller-manager 启动失败，请检查日志文件\033[0m"
    fi
done
}

deployScheduler(){
    if [[ ! -d /etc/kubernetes/pki/scheduler ]];then mkdir -p /etc/kubernetes/pki/scheduler/;fi
    # /var/log/kubernetes/scheduler 
    cd /etc/kubernetes/pki/scheduler/
    cat << EOF > /etc/kubernetes/pki/scheduler/scheduler-csr.json
{
    "CN": "system:kube-scheduler",
    "hosts": [
      "${MasterIP[0]}",
      "${MasterIP[1]}",
      "${MasterIP[2]}"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "GuangDong",
            "L": "GuangZhou",
            "O": "system:kube-scheduler",
            "OU": "Ops"
        }
    ]
}
EOF

if [[ ! -e /etc/kubernetes/pki/scheduler/scheduler-key.pem && ! -e /etc/kubernetes/pki/scheduler/scheduler.pem ]];then
    cfssl gencert -ca=/etc/kubernetes/pki/CA/ca.pem \
    -ca-key=/etc/kubernetes/pki/CA/ca-key.pem \
    -config=/etc/kubernetes/pki/CA/ca-config.json \
    -profile=kubernetes /etc/kubernetes/pki/scheduler/scheduler-csr.json | cfssljson -bare scheduler
fi

if [[ ! -f /etc/kubernetes/scheduler/scheduler.conf ]];then
    kubectl config set-cluster kubernetes \
    --certificate-authority=/etc/kubernetes/pki/CA/ca.pem \
    --embed-certs=true \
    --server=https://${k8sVIP}:8443 \
    --kubeconfig=/etc/kubernetes/pki/scheduler/scheduler.conf
    kubectl config set-credentials system:kube-scheduler \
    --client-certificate=/etc/kubernetes/pki/scheduler/scheduler.pem \
    --embed-certs=true \
    --client-key=/etc/kubernetes/pki/scheduler/scheduler-key.pem \
    --kubeconfig=/etc/kubernetes/pki/scheduler/scheduler.conf
    kubectl config set-context system:kube-scheduler@kubernetes \
    --cluster=kubernetes \
    --user=system:kube-scheduler \
    --kubeconfig=scheduler.conf
    kubectl config use-context system:kube-scheduler@kubernetes --kubeconfig=scheduler.conf 
    fi

    cat << EOF > /etc/systemd/system/kube-scheduler.service
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target
After=kube-apiserver.service

[Service]
EnvironmentFile=/usr/local/etc/kube-scheduler.conf
ExecStart=/usr/local/bin/kube-scheduler \$KUBE_SCHEDULER_ARGS
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /usr/local/etc/kube-scheduler.conf
KUBE_SCHEDULER_ARGS="--master=https://${k8sVIP}:8443 \
  --kubeconfig=/etc/kubernetes/pki/scheduler/scheduler.conf \
  --leader-elect=true \
  --logtostderr=false \
  --log-dir=/var/log/kubernetes/scheduler \
  --v=2"
EOF

for i in ${MasterIP[@]};do
    if $(ssh $i "[[ -d /etc/kubernetes/pki/scheduler ]]");then
        echo -e "\033[32m$i 已存在/etc/kubernetes/pki/scheduler/目录,跳过此步骤..........\033[0m"
    else
        ssh $i mkdir -p /etc/kubernetes/pki/scheduler/ 
    fi
    
    if $(ssh $i "[[ -d /etc/kubernetes/pki/scheduler ]]");then
        echo -e "\033[32m$i 已存在/etc/kubernetes/pki/scheduler/目录,跳过此步骤..........\033[0m"
    else
        ssh $i mkdir -p /var/log/kubernetes/scheduler/
    fi

    if $(ssh $i "[[ -f /etc/kubernetes/pki/scheduler/scheduler-key.pem ]]");then
        echo -e "\033[32m$i 已存在kube-scheduler证书私钥文件,跳过此步骤..........\033[0m"
    else
        scp /etc/kubernetes/pki/scheduler/* $i:/etc/kubernetes/pki/scheduler/
    fi

    if $(ssh $i "[[ -f /etc/systemd/system/kube-scheduler.service ]]");then
        echo -e "\033[32m$i 已存在kube-scheduler systemd service文件,跳过此步骤..........\033[0m"
    else
        scp /etc/systemd/system/kube-scheduler.service $i:/etc/systemd/system/ 
    fi

    scp /usr/local/etc/kube-scheduler.conf $i:/usr/local/etc/ 
    ssh $i "systemctl enable kube-scheduler && systemctl start kube-scheduler"
    if [ $? ];then
        echo -e "\033[32m $i kube-scheduler 启动成功\033[0m"
    else
        echo -e "\033[31m $i kube-scheduler 启动失败，请检查日志文件\033[0m"
    fi
done
}

deployKubelet(){
	kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --user=kubelet-bootstrap  &
	cd /etc/kubernetes/pki/bootstrap/ 
    echo -e "\033[32mToken是:${bootstrapToken}\033[0m"
    echo
    if [[ -f /etc/kubernetes/pki/bootstrap/boostrap.kubeconfig ]];then
        echo -e "\033[32m已存在bootstrap.kubeconfig，跳过此步骤..........\033[0m"
    else
	    kubectl config set-cluster kubernetes 	--certificate-authority=/etc/kubernetes/pki/CA/ca.pem --embed-certs=true --server=https://${k8sVIP}:8443 --kubeconfig=bootstrap.kubeconfig
	    kubectl config set-credentials kubelet-bootstrap --token=${bootstrapToken} --kubeconfig=bootstrap.kubeconfig	
	    kubectl config set-context default --cluster=kubernetes --user=kubelet-bootstrap --kubeconfig=bootstrap.kubeconfig	
	    kubectl config use-context default --kubeconfig=bootstrap.kubeconfig	
    fi

cat << EOF > /etc/systemd/system/kubelet.service
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/var/lib/kubelet
EnvironmentFile=/usr/local/etc/kubelet.conf
ExecStart=/usr/local/bin/kubelet \$KUBELET_ARGS
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

for i in ${NodeIP[@]};do
cat << EOF > /tmp/kubelet.conf
KUBELET_ARGS="--address=0.0.0.0 \\
  --hostname-override=$i \\
  --pod-infra-container-image=gcr.io/google_containers/pause-amd64:3.0 \\
  --bootstrap-kubeconfig=/etc/kubernetes/pki/bootstrap/bootstrap.kubeconfig \\
  --kubeconfig=/etc/kubernetes/pki/bootstrap/kubelet.kubeconfig \\
  --cert-dir=/etc/kubernetes/pki/bootstrap \\
  --cluster-dns=${clusterDnsIP} \\
  --cluster-domain=cluster.local. \\
  --serialize-image-pulls=false \\
  --fail-swap-on=false \\
  --logtostderr=false \\
  --log-dir=/var/log/kubernetes/kubelet \\
  --v=2"
EOF
    if $(ssh $i "[[ -d /etc/kubernetes/pki/bootstrap/ ]]");then
        echo -e "\033[32m$i 已存在/etc/kubernetes/pki/bootstrap目录,跳过此步骤..........\033[0m"
    else
    	ssh $i "mkdir -p /etc/kubernetes/pki/bootstrap/"
    fi

    if $(ssh $i "[[ -d /var/lib/kubelet ]]");then
        echo -e "\033[32m$i 已存在/var/lib/kubelet目录,跳过此步骤..........\033[0m"
    else
        ssh $i "mkdir -p /var/lib/kubelet"
    fi

    if $(ssh $i "[[ -d /var/log/kubernetes/kubelet ]]");then
        echo -e "\033[32m$i 已存在/var/log/kubernetes/kubelet目录,跳过此步骤..........\033[0m"
    else
        ssh $i "mkdir -p /var/log/kubernetes/kubelet"
    fi

    if $(ssh $i "[[ -f /etc/systemd/system/kubelet.service ]]");then
        echo -e "\033[32m$i 已存在kubelet systemd service文件,跳过此步骤..........\033[0m"
    else
    	scp /etc/systemd/system/kubelet.service $i:/etc/systemd/system/ 
    fi

    if $(ssh $i "[[ -f /etc/kubernetes/pki/bootstrap/bootstrap.kubeconfig ]]");then
        echo -e "\033[32m$i 已存在kubelet bootstrap kubeconfig文件,跳过此步骤..........\033[0m"
    else
	    scp /etc/kubernetes/pki/bootstrap/bootstrap.kubeconfig $i:/etc/kubernetes/pki/bootstrap/ 
    fi
	scp /tmp/kubelet.conf $i:/usr/local/etc/ 
	ssh $i "systemctl enable kubelet && systemctl start kubelet"
	if [ $? ];then
	    echo -e "\033[32m $i kubelet 启动成功\033[0m"
	else
	    echo -e "\033[31m $i kubelet 启动失败，请检查日志文件\033[0m"
	fi
done

# 确保在所有节点都发出了CSR之后再进行approve操作
sleep 10
if [ $? ];then
    for i in $(kubectl get csr | awk 'NR>1{print $1}' );do kubectl certificate approve $i ;done
else
	echo -e "\033[31m 未找到有CSR签署请求，请检查kubelet日志,退出脚本请按Ctrl+C\033[0m"
fi

wget https://kuberocker.oss-cn-shenzhen.aliyuncs.com/pause/3.0/pause-amd64-3.0.tar.gz -O /tmp/pause-amd64-3.0.tar.gz
for i in ${NodeIP[@]};do
    scp /tmp/pause-amd64-3.0.tar.gz $i:/tmp 
    ssh $i "docker image load -i /tmp/pause-amd64-3.0.tar.gz"
done
}

deployKubeProxy(){
    if [ ! -d /etc/kubernetes/pki/proxy ];then mkdir -p /etc/kubernetes/pki/proxy;fi
	cd /etc/kubernetes/pki/proxy
    cat << EOF > proxy-csr.json
{
    "CN": "system:kube-proxy",
    "hosts": [],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "GuangDong",
            "L": "GuangZhou",
            "O": "system:kube-proxy",
            "OU": "Ops"
        }
    ]
}
EOF

	if [[ ! -e /etc/kubernetes/pki/proxy/proxy.pem && ! -e /etc/kubernetes/pki/proxy/proxy-key.pem ]];then
		cfssl gencert -ca=/etc/kubernetes/pki/CA/ca.pem -ca-key=/etc/kubernetes/pki/CA/ca-key.pem -config=/etc/kubernetes/pki/CA/ca-config.json -profile=kubernetes proxy-csr.json | cfssljson -bare proxy	
	fi

    if [[ -f /etc/kubernetes/pki/proxy/proxy.kubeconfig  ]];then
        echo -e "\033[32m$i 已存在kube-proxy文件,跳过此步骤..........\033[0m"
    else
	    kubectl config set-cluster kubernetes --certificate-authority=/etc/kubernetes/pki/CA/ca.pem --embed-certs=true --server=https://${k8sVIP}:8443 	--kubeconfig=proxy.kubeconfig
    	kubectl config set-credentials system:kube-proxy --client-certificate=/etc/kubernetes/pki/proxy/proxy.pem --embed-certs=true --client-key=/etc/kubernetes/pki/proxy/proxy-key.pem 	--kubeconfig=proxy.kubeconfig 
        kubectl config set-context system:kube-proxy@kubernetes --cluster=kubernetes --user=system:kube-proxy --kubeconfig=proxy.kubeconfig
        kubectl config use-context system:kube-proxy@kubernetes --kubeconfig=proxy.kubeconfig
    fi

cat << EOF > /etc/systemd/system/kube-proxy.service
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
WorkingDirectory=/var/lib/kube-proxy
EnvironmentFile=/usr/local/etc/kube-proxy.conf
ExecStart=/usr/local/bin/kube-proxy \$KUBE_PROXY_ARGS
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

for i in ${NodeIP[@]};do
cat << EOF > /tmp/kube-proxy.conf
KUBE_PROXY_ARGS="--bind-address=0.0.0.0 \\
  --hostname-override=$i \\
  --cluster-cidr=${serviceNet} \\
  --kubeconfig=/etc/kubernetes/pki/proxy/proxy.kubeconfig \\
  --logtostderr=false \\
  --log-dir=/var/log/kubernetes/proxy \\
  --proxy-mode=ipvs \\
  --ipvs-scheduler=wrr \\
  --ipvs-min-sync-period=5s \\
  --ipvs-sync-period=5s \\
  --masquerade-all \\
  --v=2"
EOF

    if $(ssh $i "[[ -d /etc/kubernetes/pki/proxy ]]");then
        echo -e "\033[32m$i 已存在/etc/kubernetes/pki/proxy/目录,跳过此步骤..........\033[0m"
    else
	    ssh $i "mkdir -p /etc/kubernetes/pki/proxy/"  /var/lib/kube-proxy
    fi

    if $(ssh $i "[[ -d /var/lib/kube-proxy ]]");then
        echo -e "\033[32m$i 已存在/var/lib/kube-proxy目录,跳过此步骤..........\033[0m"
    else
	    ssh $i "mkdir -p /var/lib/kube-proxy"
    fi

    if $(ssh $i "[[ -d /var/log/kubernetes/proxy ]]");then
        echo -e "\033[32m$i 已存在/var/log/kubernetes/proxy/目录,跳过此步骤..........\033[0m"
    else
        ssh $i "mkdir -p /var/log/kubernetes/proxy/"
    fi

    if $(ssh $i "[[ -d /var/lib/kube-proxy ]]");then
        echo -e "\033[32m$i 已存在/var/lib/kube-proxy目录,跳过此步骤..........\033[0m"
    else
        ssh $i "mkdir -p /var/lib/kube-proxy"
    fi

    if $(ssh $i "[[ -f /etc/kubernetes/pki/proxy/proxy-key.pem ]]");then
        echo -e "\033[32m$i 已存在kube-proxy证书私钥文件,跳过此步骤..........\033[0m"
    else
	    scp /etc/kubernetes/pki/proxy/* $i:/etc/kubernetes/pki/proxy/ 
    fi

	scp /tmp/kube-proxy.conf $i:/usr/local/etc/ 

    if $(ssh $i "[[ -f /etc/systemd/system/kube-proxy.service ]]");then
        echo -e "\033[32m$i 已存在kube-proxy systemd service文件,跳过此步骤..........\033[0m"
    else
	    scp /etc/systemd/system/kube-proxy.service $i:/etc/systemd/system/
    fi

	ssh $i "systemctl enable kube-proxy && systemctl start kube-proxy"
	if [ $? ];then
	    echo -e "\033[32m $i kube-proxy 启动成功\033[0m"
	else
	    echo -e "\033[31m $i kube-proxy 启动失败，请检查日志文件\033[0m"
	fi
done
}

deployIngressController(){
	echo -e "\033[32m 正在部署nginx-ingress-controller.. \033[0m"
    if [ ! -e /tmp/nginx-ingress-controller-0.27.1.tar.gz ];then
        wget https://kuberocker.oss-cn-shenzhen.aliyuncs.com/ingress-controller/0.27.1/nginx-ingress-controller-0.27.1.tar.gz -O /tmp/nginx-ingress-controller-0.27.1.tar.gz
    fi
    wget https://kuberocker.oss-cn-shenzhen.aliyuncs.com/ingress-controller/0.27.1/nginx-ingress-controller-mandatory.yaml -O /tmp/nginx-ingress-controller-mandatory.yaml
    wget https://kuberocker.oss-cn-shenzhen.aliyuncs.com/ingress-controller/0.27.1/nginx-ingress-controller-service.yaml -O /tmp/nginx-ingress-controller-service.yaml
    for i in ${NodeIP[@]};do
        scp /tmp/nginx-ingress-controller-0.27.1.tar.gz /tmp/nginx-ingress-controller-mandatory.yaml $i:/tmp/
        ssh $i "docker image load -i /tmp/nginx-ingress-controller-0.27.1.tar.gz"
    done
    kubectl apply -f /tmp/nginx-ingress-controller-mandatory.yaml
    kubectl apply -f /tmp/nginx-ingress-controller-service.yaml
    sleep 5
    kubectl scale deploy -n ingress-nginx nginx-ingress-controller --replicas=${#NodeIP[@]}
}

deployCoreDNS(){
    echo
	echo -e "\033[32m 正在部署CoreDNS..... \033[0m"
   if [ ! -e /tmp/coredns-deployment-1.8.0.tar.gz ];then
        wget https://kuberocker.oss-cn-shenzhen.aliyuncs.com/coredns/1.8.0/coredns-deployment-1.8.0.tar.gz -O /tmp/coredns-deployment-1.8.0.tar.gz
        tar xvf /tmp/coredns-deployment-1.8.0.tar.gz -C /tmp
   fi
   if [ ! -e /tmp/coredns-image-1.8.0.tar.gz ];then
        wget https://kuberocker.oss-cn-shenzhen.aliyuncs.com/coredns/1.8.0/coredns-image-1.8.0.tar.gz -O /tmp/coredns-image-1.8.0.tar.gz
   fi

   for i in ${NodeIP[@]};do
        scp /tmp/coredns-image-1.8.0.tar.gz $i:/tmp/ 
        ssh $i exec docker image load -i /tmp/coredns-image-1.8.0.tar.gz
   done
   bash /tmp/deployment-master/kubernetes/deploy.sh -i ${clusterDnsIP} -s | kubectl apply -f -
   sleep 5
   kubectl scale deploy -n kube-system coredns --replicas=${#NodeIP[@]}
}

autoSSHCopy
preparation
deployHaproxyKeepalived
deployETCD
setKubectl
deployFlannel
deployApiserver
deployControllerManager
deployScheduler
deployKubelet
deployKubeProxy 
deployIngressController
deployCoreDNS
