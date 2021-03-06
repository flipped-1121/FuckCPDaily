# -*- coding: utf-8 -*-
import sys
import requests
import json
import yaml
import oss2
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from urllib3.exceptions import InsecureRequestWarning
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr

# debug模式
debug = False
if debug:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# 读取yml配置
def getYmlConfig(yaml_file='config.yml'):
    file = open(yaml_file, 'r', encoding="utf-8")
    file_data = file.read()
    file.close()
    config = yaml.load(file_data, Loader=yaml.FullLoader)
    return dict(config)


# 全局配置
config = getYmlConfig(yaml_file='config.yml')


# 获取今日校园api
def getCpdailyApis(user):
    apis = {}
    user = user['user']
    schools = requests.get(
        url='https://mobile.campushoy.com/v6/config/guest/tenant/list', verify=not debug).json()['data']
    flag = True
    for one in schools:
        if one['name'] == user['school']:
            if one['joinType'] == 'NONE':
                log(user['school'] + ' 未加入今日校园')
                exit(-1)
            flag = False
            params = {
                'ids': one['id']
            }
            res = requests.get(url='https://mobile.campushoy.com/v6/config/guest/tenant/info', params=params,
                               verify=not debug)
            data = res.json()['data'][0]
            joinType = data['joinType']
            idsUrl = data['idsUrl']
            ampUrl = data['ampUrl']
            if 'campusphere' in ampUrl or 'cpdaily' in ampUrl:
                parse = urlparse(ampUrl)
                host = parse.netloc
                res = requests.get(parse.scheme + '://' + host)
                parse = urlparse(res.url)
                apis[
                    'login-url'] = idsUrl + '/login?service=' + parse.scheme + r"%3A%2F%2F" + host + r'%2Fportal%2Flogin'
                apis['host'] = host

            ampUrl2 = data['ampUrl2']
            if 'campusphere' in ampUrl2 or 'cpdaily' in ampUrl2:
                parse = urlparse(ampUrl2)
                host = parse.netloc
                res = requests.get(parse.scheme + '://' + host)
                parse = urlparse(res.url)
                apis[
                    'login-url'] = idsUrl + '/login?service=' + parse.scheme + r"%3A%2F%2F" + host + r'%2Fportal%2Flogin'
                apis['host'] = host
            break
    if flag:
        log(user['school'] + ' 未找到该院校信息，请检查是否是学校全称错误')
        exit(-1)
    log(apis)
    return apis


# 获取当前utc时间，并格式化为北京时间
def getTimeStr():
    utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
    bj_dt = utc_dt.astimezone(timezone(timedelta(hours=8)))
    return bj_dt.strftime("%Y-%m-%d %H:%M:%S")


# 输出调试信息，并及时刷新缓冲区
def log(content):
    print(getTimeStr() + ' ' + str(content))
    sys.stdout.flush()


# 登陆并返回session
def getSession(user, loginUrl):
    user = user['user']
    params = {
        'login_url': loginUrl,
        # 保证学工号和密码正确下面两项就不需要配置
        'needcaptcha_url': '',
        'captcha_url': '',
        'username': user['username'],
        'password': user['password']
    }

    cookies = {}
    # 借助上一个项目开放出来的登陆API，模拟登陆
    res = requests.post(config['login']['api'], params, verify=not debug)
    cookieStr = str(res.json()['cookies'])
    log(cookieStr)
    if cookieStr == 'None':
        log(res.json())
        return None

    # 解析cookie
    for line in cookieStr.split(';'):
        name, value = line.strip().split('=', 1)
        cookies[name] = value
    session = requests.session()
    session.cookies = requests.utils.cookiejar_from_dict(cookies)
    return session


# 查询表单
def queryForm(session, apis):
    host = apis['host']
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 4.4.4; OPPO R11 Plus Build/KTU84P) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Safari/537.36 yiban/8.1.11 cpdaily/8.1.11 wisedu/8.1.11',
        'content-type': 'application/json',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Language': 'zh-CN,en-US;q=0.8',
        'Content-Type': 'application/json;charset=UTF-8'
    }
    queryCollectWidUrl = 'https://{host}/wec-counselor-collector-apps/stu/collector/queryCollectorProcessingList'.format(
        host=host)
    params = {
        'pageSize': 6,
        'pageNumber': 1
    }
    res = session.post(queryCollectWidUrl, headers=headers,
                       data=json.dumps(params), verify=not debug)
    if len(res.json()['datas']['rows']) < 1:
        return None

    collectWid = res.json()['datas']['rows'][0]['wid']
    formWid = res.json()['datas']['rows'][0]['formWid']

    detailCollector = 'https://{host}/wec-counselor-collector-apps/stu/collector/detailCollector'.format(
        host=host)
    res = session.post(url=detailCollector, headers=headers,
                       data=json.dumps({"collectorWid": collectWid}), verify=not debug)
    schoolTaskWid = res.json()['datas']['collector']['schoolTaskWid']

    getFormFields = 'https://{host}/wec-counselor-collector-apps/stu/collector/getFormFields'.format(
        host=host)
    res = session.post(url=getFormFields, headers=headers, data=json.dumps(
        {"pageSize": 100, "pageNumber": 1, "formWid": formWid, "collectorWid": collectWid}), verify=not debug)

    form = res.json()['datas']['rows']
    return {'collectWid': collectWid, 'formWid': formWid, 'schoolTaskWid': schoolTaskWid, 'form': form}


# 填写form
def fillForm(session, form, host):
    sort = 1
    for formItem in form[:]:
        # 只处理必填项
        if formItem['isRequired'] == 1:
            default = config['cpdaily']['defaults'][sort - 1]['default']
            if formItem['title'] != default['title']:
                log('第%d个默认配置不正确，请检查' % sort)
                exit(-1)
            # 文本直接赋值
            if formItem['fieldType'] == 1 or formItem['fieldType'] == 5:
                formItem['value'] = default['value']
            # 单选框需要删掉多余的选项
            if formItem['fieldType'] == 2:
                # 填充默认值
                formItem['value'] = default['value']
                fieldItems = formItem['fieldItems']
                for i in range(0, len(fieldItems))[::-1]:
                    if fieldItems[i]['content'] != default['value']:
                        del fieldItems[i]
            # 多选需要分割默认选项值，并且删掉无用的其他选项
            if formItem['fieldType'] == 3:
                fieldItems = formItem['fieldItems']
                defaultValues = default['value'].split(',')
                for i in range(0, len(fieldItems))[::-1]:
                    flag = True
                    for j in range(0, len(defaultValues))[::-1]:
                        if fieldItems[i]['content'] == defaultValues[j]:
                            # 填充默认值
                            formItem['value'] += defaultValues[j] + ' '
                            flag = False
                    if flag:
                        del fieldItems[i]
            # 图片需要上传到阿里云oss
            if formItem['fieldType'] == 4:
                fileName = uploadPicture(session, default['value'], host)
                formItem['value'] = getPictureUrl(session, fileName, host)
            log('必填问题%d：' % sort + formItem['title'])
            log('答案%d：' % sort + formItem['value'])
            sort += 1
        else:
            form.remove(formItem)
    # print(form)
    return form


# 上传图片到阿里云oss
def uploadPicture(session, image, host):
    url = 'https://{host}/wec-counselor-collector-apps/stu/collector/getStsAccess'.format(
        host=host)
    res = session.post(url=url, headers={
        'content-type': 'application/json'}, data=json.dumps({}), verify=not debug)
    datas = res.json().get('datas')
    fileName = datas.get('fileName')
    accessKeyId = datas.get('accessKeyId')
    accessSecret = datas.get('accessKeySecret')
    securityToken = datas.get('securityToken')
    endPoint = datas.get('endPoint')
    bucket = datas.get('bucket')
    bucket = oss2.Bucket(oss2.Auth(access_key_id=accessKeyId,
                                   access_key_secret=accessSecret), endPoint, bucket)
    with open(image, "rb") as f:
        data = f.read()
    bucket.put_object(key=fileName, headers={
        'x-oss-security-token': securityToken}, data=data)
    res = bucket.sign_url('PUT', fileName, 60)
    # log(res)
    return fileName


# 获取图片上传位置
def getPictureUrl(session, fileName, host):
    url = 'https://{host}/wec-counselor-collector-apps/stu/collector/previewAttachment'.format(
        host=host)
    data = {
        'ossKey': fileName
    }
    res = session.post(url=url, headers={
        'content-type': 'application/json'}, data=json.dumps(data), verify=not debug)
    photoUrl = res.json().get('datas')
    return photoUrl


# 提交表单
def submitForm(formWid, address, collectWid, schoolTaskWid, form, session, host):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 4.4.4; OPPO R11 Plus Build/KTU84P) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Safari/537.36 okhttp/3.12.4',
        'CpdailyStandAlone': '0',
        'extension': '1',
        'Cpdaily-Extension': 'eZbW2qLZT0G0VbYqnj5mz5UCyZiuS+Mht0ro4VCSTgTancCpi4ru3IpfZibLN2Q4JR3dl7wYTXnTi5dzfAwbYcs5FB4VPqOTrcYNVjoRY9h9J7sxA1MWIWZxiEC7iuzXwAeEjrGmnHnX3P7mprZW66fbhNsIrM938cVo6aK7fgdQx6vGY7OVJBS+kqwk/xE2ipLqV0ro4QNZ9u/6G9MUbyd7QghLIM9PIRJTrd6TzoYPFBHqDHIY57dHHUBUC8RzfvreU/2o5sY=',
        'Content-Type': 'application/json; charset=utf-8',
        # 请注意这个应该和配置文件中的host保持一致
        'Host': host,
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }

    # 默认正常的提交参数json
    params = {"formWid": formWid, "address": address, "collectWid": collectWid, "schoolTaskWid": schoolTaskWid,
              "form": form, "uaIsCpadaily": True}
    # print(params)
    submitForm = 'https://{host}/wec-counselor-collector-apps/stu/collector/submitForm'.format(
        host=host)
    r = session.post(url=submitForm, headers=headers,
                     data=json.dumps(params), verify=not debug)
    msg = r.json()['message']

    return msg


title_text = '今日校园疫结果通知'


# server酱通知
# def sendServerChan(msg):
#     log('正在发送Server酱。。。')
#     SCKEY = "SCU103057*****************************"  # 这里填Server酱官方提供的SCKEY
#     url = "https://sc.ftqq.com/%s.send" % (SCKEY)
#     res = requests.post(url, data={'text': title_text, 'desp': getTimeStr() + "\n" + str(msg)})
#     code = res.json()['errmsg']
#     if code == 'success':
#         log('发送Server酱通知成功。。。')
#     else:
#         log('发送Server酱通知失败。。。')
#         log('Server酱返回结果' + code)


# Qmsg酱通知
def sendQmsgChan(msg):
    log('正在发送Qmsg酱。。。')
    QmsgKey = "1aacce**********************"  # 这里填Qmsg酱官方提供的KEY
    url_send = "https://qmsg.zendee.cn/send/%s" % (QmsgKey)
    url_group = "https://qmsg.zendee.cn/group/%s" % (QmsgKey)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36'
    }
    payload = {'msg': '%s今日校园疫情上报自动填表结果通知' % (getTimeStr() + '\n') + '\n' + str(msg)}
    res = requests.post(url_send, params=payload, headers=headers)  # 私聊消息推送
    res_group = requests.post(url_group, params=payload, headers=headers)  # 群消息推送
    sucmsg = res.json()['success']
    if sucmsg == True:
        log('Qmsg酱通知成功')
    else:
        log('推送失败')
        log(res.json())


def main_handler(event, context):
    try:
        for user in config['users']:
            log('当前用户：' + str(user['user']['username']))
            apis = getCpdailyApis(user)
            log('脚本开始执行。。。')
            log('开始模拟登陆。。。')
            session = getSession(user, apis['login-url'])
            if session != None:
                log('模拟登陆成功。。。')
                log('正在查询最新待填写问卷。。。')
                params = queryForm(session, apis)
                if str(params) == 'None':
                    log('获取最新待填写问卷失败，可能是辅导员还没有发布。。。')
                    # sendServerChan('没有新问卷')
                    sendQmsgChan('没有新问卷')
                    exit(-1)
                log('查询最新待填写问卷成功。。。')
                log('正在自动填写问卷。。。')
                form = fillForm(session, params['form'], apis['host'])
                log('填写问卷成功。。。')
                log('正在自动提交。。。')
                msg = submitForm(params['formWid'], user['user']['address'], params['collectWid'],
                                 params['schoolTaskWid'], form, session, apis['host'])
                if msg == 'SUCCESS':
                    log('自动提交成功！')
                    # sendServerChan('🎉自动提交成功！o(*≧▽≦)ツ')
                    sendQmsgChan('🎉自动提交成功！o(*≧▽≦)ツ')
                elif msg == '该收集已填写无需再次填写':
                    log('今日已提交！')
                    # sendServerChan('🤔今日已提交！')
                    sendQmsgChan('🤔今日已提交！')
                else:
                    log('自动提交失败。。。')
                    log('错误是' + msg)
                    # sendServerChan('自动提交失败！错误是' + str(msg))
                    sendQmsgChan('自动提交失败！错误是' + str(msg))
                    exit(-1)
            else:
                log('模拟登陆失败。。。')
                log('原因可能是学号或密码错误，请检查配置后，重启脚本。。。')
                exit(-1)
    except Exception as e:
        # sendServerChan("出现问题了！" + str(e))
        sendQmsgChan("出现问题了！" + str(e))
        raise e
    else:
        return 'success'


# 配合Windows计划任务等使用
if __name__ == '__main__':
    print(main_handler({}, {}))

