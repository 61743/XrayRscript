# XrayRscript

nginx反代XrayR后端
基于wulabing的脚本修改
https://github.com/wulabing/V2Ray_ws-tls_bash_onekey

下载连接
https://raw.githubusercontent.com/61743/XrayRscript/main/insrall.sh
21行的domain是当前节点的域名
22行的host是对接的域名
23行的key是面板对接密钥
24行的id是节点id
25行的panel是面板的类型 填SSpanel或者V2board 填写参照XrayR的写法
26行的outsideport是用户连接端口
path是随机生成的 
节点服务端口 10000
nginx配置文件 /etc/nginx/conf/conf.d/zhengshu.conf 
XrayR配置文件 /etc/XrayR/config.yml

脚本配套的SSpanel节点写法 
${节点IP};10000;0;ws;tls;path=${随机生成的path}|outside_port=${用户连接端口}|host=${当前节点的域名}
V2board没用过不会配置

脚本写的比较粗糙 有能力的自行修改吧
