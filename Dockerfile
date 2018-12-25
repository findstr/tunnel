FROM FROM registry.cn-hangzhou.aliyuncs.com/findstr-vps/silly:latest
ADD packet.lua /tunnel
ADD server-src /tunnel
WORKDIR /tunnel

CMD ["./silly/silly", "server-src/config"]"

