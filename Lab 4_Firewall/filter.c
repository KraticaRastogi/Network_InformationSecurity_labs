#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>

/* This is the structure we shall use to register our function */
static struct nf_hook_ops nfho;

/* This is the hook function itself */
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	struct iphdr *iph;
	struct tcphdr *tcph;
	
	iph = ip_hdr(skb);
	tcph = (void *)iph+iph->ihl*4;
	
	if(iph->saddr == in_aton("10.0.2.5") && iph->daddr == in_aton("10.0.2.6")) {
		printk("Dropping packet from %d.%d.%d.%d to %d.%d.%d.%d", ((unsigned char *)&iph->saddr)[0], ((unsigned char *)&iph->saddr)[1], ((unsigned char *)&iph->saddr)[2], ((unsigned char *)&iph->saddr)[3], ((unsigned char *)&iph->daddr)[0], ((unsigned char *)&iph->daddr)[1], ((unsigned char *)&iph->daddr)[2], ((unsigned char *)&iph->daddr)[3]);
		return NF_DROP;
	}
	else {
		return NF_ACCEPT;	
	}
}

/* Initialization routine */
int init_module() {
	/* Fill in our hook structure */
	nfho.hook = hook_func; /* Handler function */
	nfho.hooknum = NF_INET_PRE_ROUTING; /* First hook for IPv4 */
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST; /* Make our function first */
	nf_register_hook(&nfho);
	return 0;
}

/* Cleanup routine */
void cleanup_module() {
	nf_unregister_hook(&nfho);
}