# KBI
Kubernetes Binarization Installer 
## 运行方法
```shell
bash kbi.sh
#根据提示进行操作即可，注意，输入时不能携带特殊字符
```
- 输入IP和K8s版本，即可完成K8s二进制高可用安装（含Ingress-Controller和CoreDNS）
- 最少要求3个节点，即3个Master同时作为Node来部署
- 目前只提供1.18.10的安装，其他版本正在上传至服务器中
- 网络插件为Flannel，不能更换


