<?php

namespace AppBundle\Component\OAuthClient;

class EdusohoAuthClient extends AbstractOAuthClient
{
    const USERINFO_URL = 'http://webdubilin-pay.st.edusoho.cn/me';
    const AUTHORIZE_URL = 'http://webdubilin-pay.st.edusoho.cn/ouath/authorize?';
    const OAUTH_TOKEN_URL = 'http://webdubilin-pay.st.edusoho.cn/ouath/token';

    public function getAuthorizeUrl($callbackUrl)
    {
        $params = array();
        $params['appid'] = $this->config['key'];
        $params['response_type'] = 'code';
        $params['redirect_uri'] = $callbackUrl;
        $params['scope'] = 'client_credentials';

        return self::AUTHORIZE_URL.http_build_query($params);
    }

    public function getAccessToken($code, $callbackUrl)
    {
        $params = array(
            'appid' => $this->config['key'],
            'secret' => $this->config['secret'],
            'code' => $code,
            'grant_type' => 'authorization_code',
        );
        $result = $this->getRequest(self::OAUTH_TOKEN_URL, $params);
        $rawToken = array();
        $rawToken = json_decode($result, true);
        $userInfo = $this->getUserInfo($rawToken);

        return array(
            'userId' => $userInfo['id'],
            'expiredTime' => $rawToken['expires_in'],
            'access_token' => $rawToken['access_token'],
            'token' => $rawToken['access_token'],
            'openid' => $rawToken['openid'],
        );
    }

    public function getUserInfo($token)
    {
        $params = array('access_token' => $token['access_token']);
        $params = array(
            'openid' => $token['openid'],
            'access_token' => $token['access_token'],
            'lang' => 'zh_CN', );
        $result = $this->getRequest(self::USERINFO_URL, $params);
        return json_decode($result, true);
    }
}