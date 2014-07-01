Minion MASSCAN Plugin
=====================

This is a plugin for Minion that executes the MASSCAN tool. It assumes MASSCAN is installed on your system and that is on the system PATH.

It also requires that the running user has a `NOPASSWORD` directive in the `sudoers` file for the MASSCAN binary.

Goals
-----

Thanks to MASSCAN and Minion, we should be able to grab the following aspects:

* unauthorized open ports (TCP/UDP) according to a pre-defined policy (baseline)
* authorized open ports (TCP/UDP) according to a pre-defined policy (baseline)
* information disclosure due to verbose banners

Install
-------

Minion's original `setup.sh` could be tuned to grab this plugin.

Setting up the plan
-------------------

The plan must be configured as below:

    "configuration": {
    	"interface": "eth0",
    	"source-port": 60000,
        "ports": "22,23,80,443,8080,U:53,U:69,U:161",
        "banners": [ "apache httpd", "lighthttpd", "nginx" ],
        "baseline": [
            { "address": "1.1.1.1", "udp": ["53"], "tcp": ["80", "443"] },
            { "address": "2.2.2.2", "udp": ["53"], "tcp": ["80", "443"] }
            ]
    }

Current options are:

* `interface`: send packets from specified interface (default: none, MASSCAN will use routing table)
* `source-port`: port to be set (default: none)
* `ports`: list of ports to be scanned (MASSCAN syntax) (default: will use 1000 TCP/UDP most common ports according to nmap statistics)
* `banners`: list of authorized banners (default: none)
* `baseline`: list of authorized open ports for each IP address (default: none)

Setting up the firewall
-----------------------

As MASSCAN uses its own TCP/IP stack, you have to set a firewall rule to prevent your OS to reset TCP connections as below:

    $ sudo iptables -A INPUT -p tcp --dport 60000 -j DROP

The destination port (`dport`) is defined thanks to the "source-port" argument in the masscan plan.

License
-------
This software is licensed under the MPL License. For more information, read the file ``LICENSE``.