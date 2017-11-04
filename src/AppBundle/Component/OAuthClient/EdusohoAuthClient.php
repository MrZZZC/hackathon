<?php

namespace AppBundle\Component\OAuthClient;
use AppBundle\Common\CurlToolkit;

class EdusohoAuthClient extends AbstractOAuthClient
{
    const USERINFO_URL = 'http://webdubilin-pay.st.edusoho.cn/me';
    const AUTHORIZE_URL = 'http://webdubilin-pay.st.edusoho.cn/oauth/authorize?';
    const OAUTH_TOKEN_URL = 'http://webdubilin-pay.st.edusoho.cn/oauth/token';

    public function getAuthorizeUrl($callbackUrl)
    {
        $params = array();
        $params['client_id'] = $this->config['key'];
        $params['response_type'] = 'code';
        $params['redirect_uri'] = $callbackUrl;
        $params['state'] = 'sdf';

        $url = self::AUTHORIZE_URL.http_build_query($params);

        return $url;
    }

    public function getAccessToken($code, $callbackUrl)
    {
        $params = array(
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $callbackUrl
        );

        $header = $this->config['key'] . ':' . $this->config['secret'];
        $result = array(
           'Authorization' => 'Basic '.base64_encode($header),
        );

        $result = $this->postRequest(self::OAUTH_TOKEN_URL, $params, $result);
        // $result = CurlToolkit::request('post', self::OAUTH_TOKEN_URL, $params);
        // var_dump($params);
        var_dump($result);
        $rawToken = array();
        $rawToken = json_decode($result, true);
        var_dump($rawToken);
        $userInfo = $this->getUserInfo($rawToken);
        var_dump($userInfo);exit();
        return array(
            'userId' => $userInfo['id'],
            'expiredTime' => $rawToken['expires_in'],
            'access_token' => $rawToken['access_token'],
            'token' => $rawToken['access_token'],
        );
    }

    public function getUserInfo($token)
    {
        $params = array('access_token' => $token['access_token']);
        $params = array(
            'access_token' => $token['access_token'],
        );
        $result = $this->getRequest(self::USERINFO_URL, $params);
        return json_decode($result, true);
    }
}