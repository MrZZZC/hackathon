<?php

namespace AppBundle\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Security;
use AppBundle\Component\OAuthClient\OAuthClientFactory;
use AppBundle\Component\OAuthClient\EdusohoAuthClient;

class LoginController extends BaseController
{
    public function indexAction(Request $request)
    {
        $user = $this->getCurrentUser();
        if ($user->isLogin()) {
            return $this->createMessageResponse('info', '你已经登录了', null, 3000, $this->generateUrl('homepage'));
        }

        if ($request->attributes->has(Security::AUTHENTICATION_ERROR)) {
            $error = $request->attributes->get(Security::AUTHENTICATION_ERROR);
        } else {
            $error = $request->getSession()->get(Security::AUTHENTICATION_ERROR);
        }

        if ($this->getWebExtension()->isMicroMessenger() && $this->setting('login_bind.enabled', 0) && $this->setting('login_bind.weixinmob_enabled', 0)) {
            $inviteCode = $request->query->get('inviteCode', '');

            return $this->redirect($this->generateUrl('login_bind', array('type' => 'weixinmob', '_target_path' => $this->getTargetPath($request), 'inviteCode' => $inviteCode)));
        }

        return $this->render('login/index.html.twig', array(
            'last_username' => $request->getSession()->get(Security::LAST_USERNAME),
            'error' => $error,
            '_target_path' => $this->getTargetPath($request),
        ));
    }

    public function oauthLoginAction(Request $request)
    {
        $config = array(
            'key' => $this->container->getParameter('edusoho_oauth_client_id'),
            'secret' => $this->container->getParameter('edusoho_oauth_client_secret')
        );

        $client = new EdusohoAuthClient($config);

        $loginCallBack = $this->generateUrl('oauth_call_back', array(), true);

        // return $this->redirect($loginCallBack);

        $authorizeUrl = $client->getAuthorizeUrl($loginCallBack);

        return $this->redirect($authorizeUrl);
    }

    public function oauthCallBackAction(Request $request)
    {
        $code = $request->query->get('code');

        $config = array(
            'key' => $this->container->getParameter('edusoho_oauth_client_id'),
            'secret' => $this->container->getParameter('edusoho_oauth_client_secret')
        );

        $client = new EdusohoAuthClient($config);
        $loginCallBack = $this->generateUrl('oauth_call_back', array(), true);


        $token = $client->getAccessToken($code, $loginCallBack);
        // $token = array(
        //     'userId' => '22222',
        //     'expiredTime' => 0,
        //     'access_token' => 'sssss',
        //     'token' => 'sssss',
        //     'openid' =>'2323',
        // );

        $bind = $this->getUserService()->getUserBindByTypeAndFromId('weixinweb', $token['userId']);

        $request->getSession()->set('oauth_token', $token);

        if ($bind) {
            $user = $this->getUserService()->getUser($bind['toId']);

            if (empty($user)) {
                $this->setFlashMessage('danger', 'user.bind.bind_user_not_exist');

                return $this->redirect($this->generateUrl('register'));
            }

            $this->authenticateUser($user);

            if ($this->getAuthService()->hasPartnerAuth()) {
                return $this->redirect($this->generateUrl('partner_login', array('goto' => $this->getTargetPath($request))));
            } else {
                return $this->redirect($this->generateUrl('homepage'));
            }
        } else {
            return $this->forward('AppBundle:Login:choose', array(
                'request' => $request,
                'type' => 'weixinweb',
            ));
        }

        return $this->redirect($this->generateUrl('homepage'));
    }

    public function chooseAction(Request $request, $type)
    {
        $token = $request->getSession()->get('oauth_token');
        $inviteCode = $request->query->get('inviteCode', '');
        $inviteUser = $inviteCode ? $inviteUser = $this->getUserService()->getUserByInviteCode($inviteCode) : array();

        $config = array(
            'key' => $this->container->getParameter('edusoho_oauth_client_id'),
            'secret' => $this->container->getParameter('edusoho_oauth_client_secret')
        );

        $client = new EdusohoAuthClient($config);

        try {
            $oauthUser = $client->getUserInfo($token);
            // $oauthUser = array(
            //     'name' => 'sssssss',
            //     'avatar' => 'http://ubmcmm.baidustatic.com/media/v1/0f0002tSZ9kts9soN9r_sf.jpg',
            // );
            $oauthUser['name'] = preg_replace('/[^\x{4e00}-\x{9fa5}a-zA-z0-9_.]+/u', '', $oauthUser['name']);
            $oauthUser['name'] = str_replace(array('-'), array('_'), $oauthUser['name']);
        } catch (\Exception $e) {
            $message = $e->getMessage();

            if ($message == 'unaudited') {
                $this->setFlashMessage('danger', $this->get('translator')->trans('user.bind.unaudited', array('%name%' => $clientMeta['name'])));
            } elseif ($message == 'unAuthorize') {
                return $this->redirect($this->generateUrl('login'));
            } else {
                $this->setFlashMessage('danger', $this->get('translator')->trans('user.bind.error', array('%message%' => $message)));
            }

            return $this->redirect($this->generateUrl('login'));
        }

        $name = '微信注册帐号';

        return $this->render('login/bind-choose.html.twig', array(
            'inviteUser' => $inviteUser,
            'oauthUser' => $oauthUser,
            'type' => $type,
            'name' => $name,
            'hasPartnerAuth' => $this->getAuthService()->hasPartnerAuth(),
        ));
    }

    public function ajaxAction(Request $request)
    {
        return $this->render('login/ajax.html.twig', array(
            '_target_path' => $this->getTargetPath($request),
        ));
    }

    public function checkEmailAction(Request $request)
    {
        $email = $request->query->get('value');
        $user = $this->getUserService()->getUserByEmail($email);

        if ($user) {
            $response = array('success' => true, 'message' => '该Email地址可以登录');
        } else {
            $response = array('success' => false, 'message' => '该Email地址尚未注册');
        }

        return $this->createJsonResponse($response);
    }

    public function oauth2LoginsBlockAction($targetPath, $displayName = true)
    {
        $clients = OAuthClientFactory::clients();

        return $this->render('login/oauth2-logins-block.html.twig', array(
            'clients' => $clients,
            'targetPath' => $targetPath,
            'displayName' => $displayName,
        ));
    }

    protected function getTargetPath(Request $request)
    {
        if ($request->query->get('goto')) {
            $targetPath = $request->query->get('goto');
        } elseif ($request->getSession()->has('_target_path')) {
            $targetPath = $request->getSession()->get('_target_path');
        } else {
            $targetPath = $request->headers->get('Referer');
        }

        if ($targetPath == $this->generateUrl('login', array(), true)) {
            return $this->generateUrl('homepage');
        }

        $url = explode('?', $targetPath);

        if ($url[0] == $this->generateUrl('partner_logout', array(), true)) {
            return $this->generateUrl('homepage');
        }

        if ($url[0] == $this->generateUrl('password_reset_update', array(), true)) {
            $targetPath = $this->generateUrl('homepage', array(), true);
        }

        if (strpos($targetPath, '/app.php') === 0) {
            $targetPath = str_replace('/app.php', '', $targetPath);
        }

        return $targetPath;
    }

    protected function getWebExtension()
    {
        return $this->container->get('web.twig.extension');
    }

    protected function getAuthService()
    {
        return $this->getBiz()->service('User:AuthService');
    }
}
