# -*- coding: utf-8 -*-

import requests
import json
import rsa
from bs4 import BeautifulSoup

class bmp:
    def __init__(self):
        self.Pubkey =dict();
        self.req=requests.session();
        self.LoginUrl = "https://ydxg.qust.edu.cn/cas/login?service=https%3A%2F%2Fbpm.qust.edu.cn%2Fbpmx%2Fj_spring_cas_security_check"
        self.QueryUrl="https://bpm.qust.edu.cn/bpmx/platform/bpm/bpmFormQuery/doQuery.ht"
        self.FormUrl = "https://bpm.qust.edu.cn/bpmx/platform/form/bpmDataTemplate/editData_xsjkdk.ht"
        self.SubUrl ="https://bpm.qust.edu.cn/bpmx/platform/form/bpmFormHandler/save.ht"
        self.PubKeyUrl = "https://ydxg.qust.edu.cn/cas/v2/getPubKey"
        self.dateUrl = "https://bpm.qust.edu.cn/bpmx/platform/servertime/serverTime/date.ht"
        self.formjson=json.loads('{}')
        with open("info.json") as f:
            self.formjson=json.loads(f.read())
        
        self.Form={
            "formData":'',
            "pkField": "",
            "tableId":"2000000000030000",
            "alias":"xsjkdk",
            "tableName":"xsjkdk"
        }
        self.QueryForm={
            "alias":"cxxsxx",
            "querydata":"",
            "page":1,
            "pagesize":10
        }

        self.headers = {
            'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
            'Accept': '*/*',
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7'
        }
        self.req.headers.update(self.headers)
        # self.prox={
        #     'http':'http://192.168.1.28:8888',
        #     'https':'http://192.168.1.28:8888'
        # }
        # self.req.proxies.update(self.prox)
        # self.req.verify=False

    def _encrypt(self, message, pub_key):
        keylength = rsa.common.byte_size(pub_key.n)
        padded = self._pad_for_encryption(message, keylength)

        payload = rsa.transform.bytes2int(padded)
        encrypted = rsa.core.encrypt_int(payload, pub_key.e, pub_key.n)
        block = rsa.transform.int2bytes(encrypted, keylength)
        return block

    def _pad_for_encryption(self, message, target_length):
        message = message[::-1]
        max_msglength = target_length - 11
        msglength = len(message)

        padding = b''
        padding_length = target_length - msglength - 3

        for i in range(padding_length):
            padding += b'\x00'

        return b''.join([b'\x00\x00',padding,b'\x00',message])

    def RSAEnc(self,passwd,modulus,expo):
        passwd = passwd[::-1]
        modulus = int(modulus, 16)
        exponent = int(expo, 16)
        rsa_pubkey = rsa.PublicKey(modulus, exponent)
        crypto = self._encrypt(passwd.encode(), rsa_pubkey)
        return crypto.hex()
    
    def GetPubKey(self):
        execution_ = self.req.get(self.LoginUrl).text
        soup = BeautifulSoup(execution_, 'html.parser', from_encoding='utf-8')
        for inp in soup.find_all('input'):
            if(inp.get('name')=="execution"):
                self.exid = inp.get('value')
        self.Pubkey = json.loads(self.req.get(self.PubKeyUrl).text)
    
    def Login(self,user,passwd):
        Login_from ={
            "mobileCode":"",
            "authcode":"",
            "username":user,
            "password":self.RSAEnc(passwd,self.Pubkey["modulus"],self.Pubkey["exponent"]),
            "execution":self.exid,
            "_eventId":"submit"
        }
        self.formjson["main"]["fields"]["xh"] = user
        A =  self.req.post(self.LoginUrl,data=Login_from)

    def SubmitForm(self):
        self.QueryForm["querydata"] ='{{XH:"{}"}}'.format(self.formjson["main"]["fields"]["xh"])
        userinfo = json.loads(self.req.post(self.QueryUrl,data=self.QueryForm).text)
        datat = self.req.get(self.dateUrl).text.replace('"',"")
        print("{}@{}".format(self.formjson["main"]["fields"]["xh"],datat))
        self.formjson["main"]["fields"]["xm"] = userinfo["list"][0]["XM"]
        self.formjson["main"]["fields"]["sjh"] = userinfo["list"][0]["SJHM"]
        self.formjson["main"]["fields"]["zy"] = userinfo["list"][0]["ZYMC"]
        self.formjson["main"]["fields"]["xy"] = userinfo["list"][0]["XYMC"]
        self.formjson["main"]["fields"]["bj"] = userinfo["list"][0]["BJMC"]
        self.formjson["main"]["fields"]["nj"] = userinfo["list"][0]["NJ"]
        self.formjson["main"]["fields"]["tjsj"] =datat
        self.formjson["main"]["fields"]["jssj"] = self.formjson["main"]["fields"]["tjsj"]

        for key in self.formjson["main"]["fields"]:
            self.Form["m:xsjkdk:{}".format(key)] = self.formjson["main"]["fields"][key]

        self.Form["formData"] = json.dumps(self.formjson,ensure_ascii=False)

        headers = {
            'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
            'Accept': '*/*',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
            'Origin':'https://bpm.qust.edu.cn',
            'Referer': self.FormUrl,
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7'
        }

        self.req.headers.update(headers)
        Res = self.req.post(self.SubUrl,data=self.Form)
        print(Res.text)

if __name__ == "__main__":
    bpm=bmp()
    bpm.GetPubKey()
    bpm.Login("学号","密码")
    bpm.SubmitForm()

    
