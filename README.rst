
===========
HoneyBadger
===========

.. image:: https://drone.io/github.com/david415/HoneyBadger/status.png
  :target: https://drone.io/github.com/david415/HoneyBadger/latest


project goals
-------------

* HoneyBadger will primarily be a comprehensive TCP stream analysis tool for detecting and recording TCP attacks. Perhaps it can assist in discovering 0-days and botnets.

* HoneyBadger will include a variety of TCP stream injections attacks which will prove that the TCP attack detection is reliable.



usage note
----------
It is not a good idea to run network traffic analysis tools as root.
In Linux you can run these tools as an unprivileged user after you run setcap as root like this::

   # setcap cap_net_raw,cap_net_admin=eip handshakeHijackDetector



note about the GNU AFFERO GENERAL PUBLIC LICENSE
------------------------------------------------

The HoneyBadger TCP attack detection is released under the GPL however
the "integration tests" for the TCP attack detection are in fact working
TCP exploit prototypes; therefore I have released these tools under the AGPL.
There use in the wild could be harmful... however the author
wishes to raise awareness... not help attackers.

AGPL states that if you use this software you *must*
distribute the source code along with the "publication".
It is the author's interpretation of AGPL that if you use this software
to perform TCP stream injections then you must notify users of
this fact and provide the source code to them.


=======
contact
=======
* You would like to fund my research?
* You are a malware/botnet expert and wish to collaborate?
* You want to send me pull requests?
* You like to offer me a code review?

contact info
------------
* email dstainton415@gmail.com
* gpg key ID 0x836501BE9F27A723
* gpg fingerprint F473 51BD 87AB 7FCF 6F88  80C9 8365 01BE 9F27 A723
