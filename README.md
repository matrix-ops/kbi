# KBI
Kubernetes Binarization Installer 
## 运行方法
```shell
bash kbi.sh
#根据提示进行操作即可，注意，输入时不能携带特殊字符
```
- 在所有RedHat系的发行版上（主要是RHEL/CentOS）运行此脚本，输入IP和K8s版本，即可完成K8s二进制高可用安装（含Ingress-Controller和CoreDNS）;
- 最少要求3个节点，即3个Master同时作为Node来部署;
- 理论上1.13之后的所有版本都可以安装，如果你想要的小版本在OSS中不存在，可以联系我或者你也可以自行下载server类型的tar.gz分发包，解压至所有节点的/usr/local/bin目录下，脚本检测到存在kube-apiserver文件则跳过下载kubernetes-server-XXX.tar.gz文件的步骤;
- 本着提升人机交互性的原则(主要是懒），工具暂时不提供命令行选项。如果需要安装的节点超过10个以上，可以联系我或者你也可以把所有IP以空格分隔直接粘贴进去;
- 网络插件为Flannel，后端为VXLAN，暂时不能更换;
- 所有二进制文件都存储在阿里云华南区OSS中(流量宝贵且是个人自费，请大侠不要DDOS我，跪谢XD），已上传至OSS的版本如下;
> - 1.16.15
> - 1.17.14
> - 1.18.10
> - 1.19.4


