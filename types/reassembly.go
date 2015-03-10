/*
 *    I include google's license because this code is copy-pasted and refactored
 *    from the original, Google's gopacket.tcpassembly...
 *    Thanks to Graeme Connel for writing tcpassembly!
 */
// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD file in the root of the source
// tree.

package types

import (
	"fmt"
	"time"
)

// Reassembly is used to represent a TCP segment
type Reassembly struct {
	// Seq is the TCP sequence number for this segment
	Seq Sequence

	// Bytes is the next set of bytes in the stream.  May be empty.
	Bytes []byte
	// Skip is set to non-zero if bytes were skipped between this and the
	// last Reassembly.  If this is the first packet in a connection and we
	// didn't see the start, we have no idea how many bytes we skipped, so
	// we set it to -1.  Otherwise, it's set to the number of bytes skipped.
	Skip int
	// Start is set if this set of bytes has a TCP SYN accompanying it.
	Start bool
	// End is set if this set of bytes has a TCP FIN or RST accompanying it.
	End bool
	// Seen is the timestamp this set of bytes was pulled off the wire.
	Seen time.Time
}

// String returns a string representation of Reassembly
func (r Reassembly) String() string {
	return fmt.Sprintf("Reassembly: Seq %d Bytes len %d Skip %d Start %v End %v Seen %s", r.Seq, len(r.Bytes), r.Skip, r.Start, r.End, r.Seen)
}
