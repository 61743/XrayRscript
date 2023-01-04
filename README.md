# XrayRscript

nginx反代XrayR后端  
基于 @wulabing 的脚本修改  
参见https://github.com/wulabing/V2Ray_ws-tls_bash_onekey  

在cloudflare给节点解析一个域名给节点就好
一键脚本  
`wget https://raw.githubusercontent.com/61743/XrayRscript/main/install.sh && bash install.sh`

脚本配套的SSpanel节点写法   
${节点IP};${服务端监听端口};0;ws;tls;path=${path}|outside_port=${用户连接端口}|host=${当前节点的域名}  
V2board没用过不会配置  

telegram群组 https://t.me/XrayR61743_group
