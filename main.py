from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr, IPAddr
import os
import csv


log = core.getLogger()
aclSrc = "%s/pox/pox/firewall/nw_policies.csv" % os.environ[ 'HOME' ]



class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        self.firewall = {}
        log.info("Starting Firewall")

    def pushRuleToSwitch (self, src, dst, proto, duration = 0):
        # creating a switch flow table entry
        msg = of.ofp_flow_mod()
        msg.priority = 20
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))

        # creating a match structure
        match = of.ofp_match()

        # set packet ethernet type as IP
        match.dl_type = 0x800;

        # IP protocol match
        if proto == "icmp":
           match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
        elif proto == "tcp":
           match.nw_proto = pkt.ipv4.TCP_PROTOCOL
        elif proto == "udp":
           match.nw_proto = pkt.ipv4.UDP_PROTOCOL


        # flow rule for src:host1 dst:host2
        match.nw_src = IPAddr(src)
        match.nw_dst = IPAddr(dst)
        msg.match = match
        self.connection.send(msg)

        # flow rule for src:host2 dst:host1
        match.nw_src = IPAddr(dst)
        match.nw_dst = IPAddr(src)
        msg.match = match
        self.connection.send(msg)



    def AddRule (self, src=0, dst=0, proto=0, value=True):
        if (src, dst, proto) in self.firewall:
            log.warning("Rule exists: drop: src %s - dst %s - proto %s", src, dst, proto)
        else:
            self.firewall[(src, dst, proto)]=value
            self.pushRuleToSwitch(src, dst, proto, 10000)
            log.info("Rule added: drop: src %s - dst %s - proto %s", src, dst, proto)


    def _handle_ConnectionUp (self, event):
        acl  = open(aclSrc, "rb")

        self.connection = event.connection

        rulesIterator = csv.reader(acl)
        for rule in rulesIterator:
            print rule[0]
            if rule[0] != "id" :
                self.AddRule(rule[1], rule[2], rule[3])


        log.info("Firewall rules pushed on the switch id: %s", dpidToStr(event.dpid))

def launch ():
    core.registerNew(Firewall)

