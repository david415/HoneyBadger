// +build darwin
// +build amd64

/*
 * This file was inspired by BSD licensed code from https://github.com/songgao/ether
 *
 * ( http://opensource.org/licenses/BSD-3-Clause )
 *
 */

package bpf_sniffer

import "syscall"

/*
 * From bpf.h:
 *
 *  struct bpf_hdr {
 *      struct BPF_TIMEVAL bh_tstamp;
 *      bpf_u_int32 bh_caplen;
 *      bpf_u_int32 bh_datalen;
 *      u_short bh_hdrlen;
 *  };
 *
 */

type timeval struct {
	syscall.Timeval32
}

func (t *timeval) Unix() (sec int64, nsec int64) {
	return int64(t.Sec), int64(t.Usec) * 1000
}

type bpf_hdr struct {
	bh_tstamp  timeval // 8 bytes
	bh_caplen  uint32
	bh_datalen uint32
	bh_hdrlen  uint16
}
