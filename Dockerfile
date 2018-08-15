FROM registry.cn-hangzhou.aliyuncs.com/findstr-vps/silly:latest
ADD packet.lua /tunnel/packet.lua
ADD server-src /tunnel/server-src
WORKDIR /tunnel

CMD ["./silly/silly", "server-src/config"]"

