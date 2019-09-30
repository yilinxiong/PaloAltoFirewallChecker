import re
import sys
import ipaddress
from functools import partial
from socket import gethostbyname

from pandevice.firewall import Firewall
from pandevice.policies import SecurityRule, Rulebase
from pandevice.objects import AddressObject, ServiceObject, ApplicationObject


class IPv4Range(object):
    def __init__(self, iprange):
        ip_suffix = re.sub('\d+-\d+', '', iprange)
        _ip_first, _ip_last = iprange.split('.')[-1].split('-')
        if not(_ip_first.isdigit() and _ip_last.isdigit()):
            raise ValueError("Invalid ip-range value, use format like 10.1.1.1-2")
        elif int(_ip_first) < 0 or int(_ip_first) > int(_ip_last) or int(_ip_last) > 255:
            raise ValueError("Invalid ip-range value, use format like 10.1.1.1-2")
        
        self._first_ip = ipaddress.ip_address(unicode(ip_suffix+_ip_first))
        self._last_ip = ipaddress.ip_address(unicode(ip_suffix+_ip_last))
        self._num_addresses = int(_ip_last) - int(_ip_first)
        
    @property
    def first_ip(self):
        return self._first_ip
    
    @property
    def last_ip(self):
        return self._last_ip

    @property
    def num_addresses(self):
        return self._num_addresses

    def __contains__(self, item):
        if not isinstance(item, (IPv4Network, IPv4Address, IPv4Range)):
            return False

        return self.first_ip <= item.first_ip and self.last_ip >= item.last_ip


class IPv4Address(ipaddress.IPv4Address):
    @property
    def first_ip(self):
        return self

    @property
    def last_ip(self):
        return self

    @property
    def num_addresses(self):
        return 1

    def __contains__(self, item):
        if not isinstance(item, IPv4Address):
            return False

        return item == self


class IPv4Network(ipaddress.IPv4Network):
    @property
    def first_ip(self):
        return self.network_address

    @property
    def last_ip(self):
        return self.broadcast_address

    def __contains__(self, item):
        if not isinstance(item, (IPv4Network, IPv4Address, IPv4Range)):
            return False

        return self.first_ip <= item.first_ip and self.last_ip >= item.last_ip


class PanAddressObject(AddressObject):
    def __str__(self):
        return "{} Name:{} Location:{} Type:{} Address:{}".format(self.__class__.__name__, self.name, self.vsys, self.ip_type, self.address)

    @property
    def address(self):
        element = self.element()
        _address = element.getchildren()[0].text
        if self.ip_type == 'ip-netmask':
            return IPv4Network(unicode(_address))
        elif self.ip_type == 'ip-range':
            return IPv4Range(unicode(_address))
        elif self.ip_type == 'fqdn':
            return IPv4Address(unicode(gethostbyname(_address)))
        else:
            return IPv4Address(unicode("255.255.255.255"))

    @property
    def ip_type(self):
        element = self.element()
        return element.getchildren()[0].tag

    def __contains__(self, item):
        return item in self.address


def find_service(*args):
    service_str = args[0]
    service_obj = args[1]
    protocol, port = service_str.split("/")
    if protocol.lower() == service_obj.protocol.lower():
        dport = service_obj.destination_port
        if ',' in dport:
            return port in dport.split(',')
        elif '-' in dport:
            start_port, end_port = dport.split('-')
            return int(start_port) <= int(port) <= int(end_port)
        else:
            return dport == port


def test_traffic(*args):
    srca = args[0]
    dsta = args[1]
    app = args[2]
    srv = args[3]
    rule = args[4]
    src_matched = dst_matched = app_matched = srv_matched = is_allowed = False
    if "any" in rule.source:
        src_matched = True
    elif srca:
        for s in srca:
            if s.name in rule.source:
                src_matched = True
                break

    if "any" in rule.destination:
        dst_matched = True
    elif dsta:
        for d in dsta:
            if d.name in rule.destination:
                dst_matched = True
                break

    if app is None or "any" in rule.application:
        app_matched = True
    else:
        if app in rule.application:
            app_matched = True

    if "any" in rule.service:
        srv_matched = True
    elif srv:
        for s in srv:
            if s.name in rule.service:
                srv_matched = True
                break

    if rule.action == "allow":
        is_allowed = True

    return all((src_matched, dst_matched, app_matched, srv_matched, is_allowed))


if __name__ == "__main__":
    import config

    vsys = Firewall(config.host, config.api_username, config.api_password, serial=config.fw_serial, is_virtual=True, vsys=config.vsys)
    shared = Firewall(config.host, config.api_username, config.api_password, serial=config.fw_serial, is_virtual=True, vsys=config.shared_vsys)

    # Pull all address objects in vsys and shared configuration
    address = PanAddressObject.refreshall(shared)
    address.extend(PanAddressObject.refreshall(vsys))

    # Pull all policies in vsys and filter security rules out
    rulebase = Rulebase.refreshall(vsys)
    security_rules = filter(lambda x: isinstance(x, SecurityRule), rulebase[0].children)

    # Pull all service objects from vsys and shared configuration
    all_services = ServiceObject.refreshall(vsys)
    all_services.extend(ServiceObject.refreshall(shared))

    # Check if source ip address is included in any address objects
    src = sys.argv[1]
    src_ip = IPv4Address(unicode(src))
    src_addr_objects = [_address for _address in address if src_ip in _address]

    # Check if destination ip address is included in any address objects
    dst = sys.argv[2]
    dst_ip = IPv4Address(unicode(dst))
    dst_addr_objects = [_address for _address in address if dst_ip in _address]

    # Check if service is included in any service objects
    service = sys.argv[3]
    services = filter(partial(find_service, service), all_services)

    application = sys.argv[4]

    # Filter the matched security rules which is allowing the traffic
    find_secu = partial(test_traffic, src_addr_objects, dst_addr_objects, application, services)
    matched_rules = filter(find_secu, security_rules)

    if matched_rules:
        print "Test traffic src: {}, dst: {}, service: {}, application: {}".format(src, dst, service, application)
        for rule in matched_rules:
            print "Found Security Rule: " + rule.name

    else:
        print "Traffic src: {}, dst: {}, service: {}, application: {} is denied!".format(src, dst, service, application)
      
