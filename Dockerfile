FROM registry.cn-hangzhou.aliyuncs.com/findstr-vps/silly:latest
ADD packet.lua /packet.lua
ADD server-src /server-src
ADD common.conf /common.conf
WORKDIR /

CMD ["server-src/config"]"

