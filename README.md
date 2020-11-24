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
- 理论上1.13之后的所有版本都可以安装，如果你想要的小版本在OSS中不存在，可以联系我或者你也可以自行下载server类型的tar.gz分发包，解压至/usr/local/bin目录下，脚本检测到存在kube-apiserver文件则跳过下载kubernetes-server-XXX.tar.gz文件的下载。
- 本着提升人机交互性的原则，工具暂时不提供命令行选项。如果需要安装的节点超过100个以上，可以联系我或者你也可以将100个IP每个IP以空格分隔直接粘贴进去。
- 网络插件为Flannel，后端为VXLAN，暂时不能更换


