// +build freebsd openbsd netbsd darwin,386

/*
 * This file was inspired by BSD licensed code from https://github.com/songgao/ether
 *
 * ( http://opensource.org/licenses/BSD-3-Clause )
 *
 */

package bpf_sniffer

import "syscall"

/*
 * struct bpf_hdr {
 *   struct bpf_timeval bh_tstamp;
 *     u_int32_t	bh_caplen;
 *     u_int32_t	bh_datalen;
 *     u_int16_t	bh_hdrlen;
 * };
 */

type bpf_hdr struct {
	bh_tstamp  syscall.Timeval // 8 or 16 bytes depending on arch
	bh_caplen  uint32
	bh_datalen uint32
	bh_hdrlen  uint16
}
