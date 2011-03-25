#include <linux/module.h>  /* needed by all modules */
#include <linux/kernel.h>  /* needed for KERN_INFO */
#include <linux/init.h>    /* needed for various convenience macros */
#include <linux/proc_fs.h> /* needed to interact with /proc/ */
#include <asm/uaccess.h>   /* for copy_from_user */
#include <net/tcp.h>
#include <net/ip.h>

#define PROCFILENAME "sk_shiftbits"
struct proc_dir_entry* procfile;

#define MODULENAME "mod_skewmask"

/*
 * shift_bits parameter.  Install the module with "insmod mod_skewmask
 * shift_bits=n" to set the number of bits to shift TSopt clock values.
 */
static short int shift_bits = 3;
module_param(shift_bits, short, S_IRUSR | S_IWUSR |  S_IRGRP | S_IROTH);
MODULE_PARM_DESC(shift_bits,
        "Shift TSopt clock value left by this many bits");

static struct packet_type myproto;

/*
 * emit the contents of the shift_bits parameter as a string into the
 * provided buffer.
 */
static int
procfile_read(char *buffer, char** buffer_location,
        off_t offset, int buffer_length, int *eof, void *data)
{
    return (offset > 0)
        ? 0
        : snprintf(buffer, buffer_length, "%d\n", shift_bits);
}

/*
 * write a new value to the shift_bits parameter.
 */
static int
procfile_write(struct file* file, const char* __user buffer,
        unsigned long count, void *data)
{
    char buf[6];
    short int sb = shift_bits;
    size_t len = min((unsigned long)sizeof(buf) - 1, count);
    char* nl;

    /* try copying the new sb value from user-space to kernel-space */
    if (copy_from_user(buf, buffer, len))
        return count; /* this is actually bad */
    buf[len] = '\0';
    for (nl = buf; *nl != '\0'; ++nl) {
        if (*nl == '\n')
            *nl = '\0';
    }
    printk(KERN_INFO MODULENAME ": got '%s'\n", buf);

    /* after some checking, copy the new sb value to our shift_bits
     * parameter */
    if (sscanf(buf, "%hd", &sb) != 1)
        printk(KERN_INFO MODULENAME
                ": %s is not a valid short", buf);
    else if (sb < 0 || sb > 32)
        printk(KERN_INFO MODULENAME
                ": %s is not between 0 and 32", buf);
    else
        shift_bits = sb;

    return 1; /* this value doesn't actually matter */
}

static int
mysendfn (struct sk_buff *skb,
        struct net_device *dv,
        struct packet_type *pt)
{
    u32 stamp_orig, stamp;
    struct tcphdr* th = tcp_hdr(skb);
    struct tcp_options_received tmp_opt;
    u32* tsptr;
    u32* ckptr;

    /* we want to touch only outgoing TCP packets */
    if (ntohs(skb->protocol) != ETH_P_IP) goto cleanup;
    if (skb->pkt_type != PACKET_OUTGOING) goto cleanup;
    if (ip_hdr(skb)->protocol != IPPROTO_TCP) goto cleanup;

    /* read the stamp from the outgoing packet */
    stamp_orig = TCP_SKB_CB(skb)->when;
    if (!stamp_orig) goto cleanup;

    /* XXX comment me */
    tsptr = th;
    tsptr += 11;
    if (ntohl(*tsptr)!=stamp_orig) { tsptr++; } /* try the next byte */
    if (ntohl(*tsptr)==stamp_orig) {
        if (stamp_orig & 1) {
            printk(KERN_DEBUG MODULENAME
                    ": fixing ts; %08x->%08x\n",
                    ntohl(*tsptr), stamp_orig & ~1);
            *tsptr = htonl(stamp_orig & ~1);
            TCP_SKB_CB(skb)->when = stamp_orig & ~1;
            /* XXX HACK: fix up checksum manually! */
            ckptr = tsptr;
            ckptr -= 3;
            printk(KERN_DEBUG MODULENAME ": orig cksum %04x\n",
                    ntohl(*ckptr));
            *ckptr += htonl(1); /* simply increment the checksum */
            printk(KERN_DEBUG MODULENAME ":  new cksum %04x\n",
                    ntohl(*ckptr));
        }
    }

cleanup:
    kfree_skb(skb);
    return 0; /* XXX this return value doesn't seem to matter */
}


/*
 * Hook into the sending stack.
 */
static void init_proto (void) {
    myproto.type = htons(ETH_P_ALL);
    myproto.func = mysendfn;
    myproto.dev = NULL; /* NULL means get packets from all devices */
    dev_add_pack(&myproto);
}

/*
 * Module initialization routine.
 */
static int __init skewmask_init (void) {
    printk(KERN_INFO "Installing mod_skewmask (shift_bits=%d)\n",
            shift_bits);

    /*
     * Attempt to create /proc/PROCFILENAME.  If this fails, assume
     * we're out of memory.  Otherwise, set various parts so that the
     * result looks like this:
     *
     *   -rw-r--r-- 1 root root 1 2007-12-06 16:27 /proc/sk_shiftbits
     *
     */
    procfile = create_proc_entry(PROCFILENAME, 0644, NULL);
    if (procfile == NULL) {
        remove_proc_entry(PROCFILENAME, NULL);
        printk(KERN_ALERT "Error: unable to create /proc/%s\n",
                PROCFILENAME);
        /* blame an out of memory error (ENOMEM). */
        return -ENOMEM;
    }
    procfile->read_proc = procfile_read;
    procfile->write_proc = procfile_write;
    procfile->owner = THIS_MODULE; /* this is defined, don't worry */
    procfile->mode = S_IFREG | S_IRUGO | S_IWUSR;
    procfile->uid = procfile->gid = 0;
    procfile->size = 1; /* XXX */
    printk(KERN_INFO "Created /proc/%s\n", PROCFILENAME);

    /*
     * Hook into the kernel's sending stack
     */
    init_proto();

    return 0;
}

/*
 * Module exit routine.  Clean up if necessary.
 */
static void __exit skewmask_exit (void) {
    dev_remove_pack(&myproto);
    remove_proc_entry(PROCFILENAME, NULL);
    printk(KERN_INFO "Removed /proc/%s\n", PROCFILENAME);
    printk(KERN_INFO "Uninstalling mod_skewmask\n");
}

/*
 * Tell the kernel what our init and exit routines are called.
 */
module_init(skewmask_init);
module_exit(skewmask_exit);

/*
 * Metadata so that the kernel doesn't complain about non-free software.
 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("{ransford,elisha}@cs.umass.edu");
MODULE_DESCRIPTION("Masks clock skew by futzing with TSopt values.");
