#ifndef	_TUNNEL_H
#define	_TUNNEL_H

struct tunnel_config {
	char lip[64]; //listen ip
	int lport; //listen port
	char sip[64]; //server ip
	int sport; //server port
	char key[256];
};

struct buffer {
	uint8_t *data;
	size_t  datasz;
	size_t  datacap;
};

struct tunnel {
	int s;	//socket
	int t;	//tunnel socket
	int state;
	struct {
		struct buffer send;
		struct buffer recv;
	} sock;
	struct {
		struct buffer send;
		struct buffer recv;
	} tunnel;
	struct buffer buff;	//for compact
	const struct tunnel_config *cfg;
	struct tunnel *next;
	struct tunnel *prev;
};

struct tunnel *tunnel_create(int fd, struct tunnel_config *cfg);
void tunnel_free(struct tunnel *t);

int tunnel_recv(struct tunnel *t);
int tunnel_process(struct tunnel *t);

static inline void
tosockaddr(struct sockaddr *addr, const char *ip, int port)
{
	struct sockaddr_in *in = (struct sockaddr_in *)addr;
	bzero(addr, sizeof(*addr));
	in->sin_family = AF_INET;
	in->sin_port = htons(port);
	inet_pton(AF_INET, ip, &in->sin_addr);
}


#endif

