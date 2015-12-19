<?php

use Topxia\Api\Util\UserUtil;
use Topxia\Common\ArrayToolkit;
use Topxia\Service\Common\ServiceKernel;
use Symfony\Component\HttpFoundation\Request;

$api = $app['controllers_factory'];

/*
## 用户模糊查询

GET /users

 ** 参数 **

| 名称  | 类型  | 必需   | 说明 |
| ---- | ----- | ----- | ---- |
| q | string | 是 | 用于匹配的字段值,分别模糊匹配手机,qq,昵称,每种匹配返回一个列表,每个列表最多五个 |

 ** 响应 **

```
{
"mobile": [
datalist
],
"qq": [
datalist
],
"nickname": [
datalist
]
}
```
 */
$api->get('/', function (Request $request) {
    $field = $request->query->get('q');
    $mobileProfiles = ServiceKernel::instance()->createService('User.UserService')->searchUserProfiles(array('mobile' => $field), array('id', 'DESC'), 0, 5);
    $qqProfiles = ServiceKernel::instance()->createService('User.UserService')->searchUserProfiles(array('qq' => $field), array('id', 'DESC'), 0, 5);

    $mobileList = ServiceKernel::instance()->createService('User.UserService')->findUsersByIds(ArrayToolkit::column($mobileProfiles, 'id'));
    $qqList = ServiceKernel::instance()->createService('User.UserService')->findUsersByIds(ArrayToolkit::column($qqProfiles, 'id'));
    $nicknameList = ServiceKernel::instance()->createService('User.UserService')->searchUsers(array('nickname' => $field), array('LENGTH(nickname)', 'ASC'), 0, 5);
    return array(
        'mobile'   => filters($mobileList, 'user'),
        'qq'       => filters($qqList, 'user'),
        'nickname' => filters($nicknameList, 'user')
    );
}

);

/*
## 分页获取全部用户

GET /users/pages

 ** 参数 **

| 名称  | 类型  | 必需   | 说明 |
| ---- | ----- | ----- | ---- |

 ** 响应 **

```
{
'data': [
datalist
],
"total": {total}
}
```
 */
$api->get('/pages', function (Request $request) {
    $start = $request->query->get('start', 0);
    $limit = $request->query->get('limit', 10);
    $count = ServiceKernel::instance()->createService('User.UserService')->searchUserCount(array());
    $users = ServiceKernel::instance()->createService('User.UserService')->searchUsers(array(), array('createdTime', 'DESC'), $start, $limit);
    return array(
        'data'  => filters($users, 'user'),
        'total' => $count
    );
}

);

//根据id获取一个用户信息

$api->get('/{id}', function (Request $request, $id) {
    $user = convert($id, 'user');
    return filter($user, 'user');
}

);

/*
## 注册

POST /users/

 ** 参数 **

| 名称  | 类型  | 必需   | 说明 |
| ---- | ----- | ----- | ---- |
| email | string | 是 | 邮箱 |
| nickname | string | 是 | 昵称 |
| password | string | 是 | 密码 |

 ** 响应 **

```
{
"xxx": "xxx"
}
```
 */
$api->post('/', function (Request $request) {
    $fields = $request->request->all();

    if (!ArrayToolkit::requireds($fields, array('email', 'nickname', 'password'))) {
        return array('message' => '缺少必填字段');
    }

    $ip = $request->getClientIp();
    $fields['createdIp'] = $ip;

    $authSettings = ServiceKernel::instance()->createService('System.SettingService')->get('auth', array());

    if (isset($authSettings['register_protective'])) {
        $type = $authSettings['register_protective'];

        switch ($type) {
            case 'middle':
                $condition = array(
                    'startTime' => time() - 24 * 3600,
                    'createdIp' => $ip);
                $registerCount = ServiceKernel::instance()->createService('User.UserService')->searchUserCount($condition);

                if ($registerCount > 30) {
                    goto failure;
                }

                goto register;
                break;
            case 'high':
                $condition = array(
                    'startTime' => time() - 24 * 3600,
                    'createdIp' => $ip);
                $registerCount = ServiceKernel::instance()->createService('User.UserService')->searchUserCount($condition);

                if ($registerCount > 10) {
                    goto failure;
                }

                $registerCount = ServiceKernel::instance()->createService('User.UserService')->searchUserCount(array(
                    'startTime' => time() - 3600,
                    'createdIp' => $ip));

                if ($registerCount >= 1) {
                    goto failure;
                }

                goto register;
                break;
            default:
                goto register;
                break;
        }
    }

    register:
    $user = ServiceKernel::instance()->createService('User.UserService')->register($fields);
    return filter($user, 'user');

    failure:
    return array('message' => '已经超出用户注册次数限制，用户注册失败');
}

);

/*

## 登录

POST /users/login

 ** 参数 **

| 名称  | 类型  | 必需   | 说明 |
| ---- | ----- | ----- | ---- |
| nickname | string | 是 | 昵称 |
| password | string | 是 | 密码 |

 ** 响应 **

```
{
"xxx": "xxx"
}
```
 */
$api->post('/login', function (Request $request) {
    $fields = $request->request->all();
    $user = ServiceKernel::instance()->createService('User.UserService')->getUserByLoginField($fields['nickname']);

    if (empty($user)) {
        throw new \Exception('user not found');
    }

    if (!ServiceKernel::instance()->createService('User.UserService')->verifyPassword($user['id'], $fields['password'])) {
        throw new \Exception('password error');
    }

    $token = ServiceKernel::instance()->createService('User.UserService')->makeToken('mobile_login', $user['id']);
    setCurrentUser($user);
    return array(
        'user'  => filter($user, 'user'),
        'token' => $token
    );
}

);

/*

## 第三方登录

POST /users/bind_login

 ** 参数 **

| 名称  | 类型  | 必需   | 说明 |
| ---- | ----- | ----- | ---- |
| type | string | 是 | 第三方类型,值有qq,weibo,weixin,renren |
| id | string | 是 | 第三方处的用户id |
| name | string | 是 | 第三方处的用户昵称 |
| avatar | string | 是 | 第三方处的用户头像 |

 ** 响应 **

```
{
"user": "{user-data}"
"token": "{user-token}"
}
```

此处`token`为ES端记录通过接口登录的用户的唯一凭证

 */
$api->post('/bind_login', function (Request $request) {
    $type = $request->request->get('type');
    $id = $request->request->get('id');
    $name = $request->request->get('name');
    $avatar = $request->request->get('avatar', '');

    if (empty($type)) {
        throw new \Exception('type parameter error');
    }

    $userBind = ServiceKernel::instance()->createService('User.UserService')->getUserBindByTypeAndFromId($type, $id);

    if (empty($userBind)) {
        $oauthUser = array(
            'id'        => $id,
            'name'      => $name,
            'avatar'    => $avatar,
            'createdIp' => $request->getClientIp()
        );
        $token = array('userId' => $id);

        if (empty($oauthUser['id'])) {
            throw new \RuntimeException("获取用户信息失败，请重试。");
        }

        if (!ServiceKernel::instance()->createService('User.AuthService')->isRegisterEnabled()) {
            throw new \RuntimeException("注册功能未开启，请联系管理员！");
        }

        $userUtil = new UserUtil();
        $user = $userUtil->generateUser($type, $token, $oauthUser, $setData = array());

        if (empty($user)) {
            throw new \RuntimeException("登录失败，请重试！");
        }

        $token = ServiceKernel::instance()->createService('User.UserService')->makeToken('mobile_login', $user['id']);
        setCurrentUser($user);
        $user = $userUtil->fillUserAttr($user['id'], $oauthUser);
    } else {
        $user = ServiceKernel::instance()->createService('User.UserService')->getUser($userBind['toId']);
        $token = ServiceKernel::instance()->createService('User.UserService')->makeToken('mobile_login', $user['id']);
        setCurrentUser($user);
    }

    return array(
        'user'  => filter($user, 'user'),
        'token' => $token
    );
}

);

/*
## 登出

POST /users/logout

 ** 响应 **

```
{
"success": bool
}
```
 */
$api->post('/logout', function (Request $request) {
    $token = $request->request->get('token');
    $result = ServiceKernel::instance()->createService('User.UserService')->deleteToken('login', $token);
    return array(
        'success' => $result ? $result : false
    );
}

);

/*
## （取消）关注用户
POST /users/{id}/followers

 ** 参数 **

| 名称  | 类型  | 必需   | 说明 |
| ---- | ----- | ----- | ---- |
| method | string | 否 | 值为delete时为取消关注用户 |

 ** 响应 **

```
{
"success": bool
}
```
 */
$api->post('/{id}/followers', function (Request $request, $id) {
    $method = $request->request->get('method');
    $fromUser = getCurrentUser();
    if (!empty($method) && $method == 'delete') {
        $result = ServiceKernel::instance()->createService('User.UserService')->unFollow($fromUser['id'], $id);
    } else {
        $result = ServiceKernel::instance()->createService('User.UserService')->follow($fromUser['id'], $id);
    }

    return array(
        'success' => empty($result) ? false : true
    );
}

);
return $api;
