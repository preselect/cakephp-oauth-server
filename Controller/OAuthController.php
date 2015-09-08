<?php

/**
 * CakePHP OAuth Server Plugin
 *
 * This is an example controller providing the necessary endpoints
 *
 * @author Thom Seddon <thom@seddonmedia.co.uk>
 * @see https://github.com/thomseddon/cakephp-oauth-server
 *
 */
App::uses('OAuthAppController', 'OAuth.Controller');

/**
 * OAuthController
 *
 */
class OAuthController extends OAuthAppController {

        public $components = array(
            'OAuth.OAuth',
            'Auth' => array(
                'authenticate' => array(
                    'Ip' => array(
                        'userModel' => 'User',
                        'fields' => array('ipAddresses' => 'ip_addresses', 'excludedIpAddresses' => 'excluded_ip_addresses'),
                        'contain' => false,
                        'scope' => array('User.active' => 1)
                    ),
                    'Form' => array(
                        'contain' => false,
                        'scope' => array('User.active' => 1)
                    ),
                    'Saml' => array(
                        'userModel' => 'User',
                        'fields' => array('Saml' => 'saml'),
                        'contain' => false,
                        'scope' => array('User.active' => 1)
                    ),
                    'Code' => array(
                        'userModel' => 'User',
                        'fields' => array('useCode' => 'use_code'),
                        'codeModel' => 'Code',
                        'timeout' => 3600,
                        'contain' => false,
                        'scope' => array('User.active' => 1)
                    )
                )
            ),
            'Session',
            'Security'
        );
        public $uses = array('User');
        public $helpers = array('Form');
        private $blackHoled = false;

        /**
         * beforeFilter
         *
         */
        public function beforeFilter() {
                parent::beforeFilter();
                $this->Auth->allow($this->OAuth->allowedActions);
                $this->Security->blackHoleCallback = 'blackHole';
        }

        /**
         * Example Authorize Endpoint
         *
         * Send users here first for authorization_code grant mechanism
         *
         * Required params (GET or POST):
         * 	- response_type = code
         * 	- client_id
         * 	- redirect_url
         *
         */
        public function authorize($account_id = null) {
                if (!$this->Auth->loggedIn()) {
                        $this->redirect(array('action' => 'login', '?' => $this->request->query));
                }
                $this->validateRequest();

                if ($this->Session->check('OAuth.params')) {
                        $OAuthParams = $this->Session->read('OAuth.params');
                        $this->Session->delete('OAuth.params');
                } else {
                        try {
                                $OAuthParams = $this->OAuth->getAuthorizeParams();
                        } catch (Exception $e) {
                                $e->sendHttpResponse();
                        }
                }
                $userId = $this->Auth->user('id');

                if ($this->Session->check('OAuth.logout')) {
                        $this->Auth->logout();
                        $this->Session->delete('OAuth.logout');
                }


                $OAuthParams = array_merge($OAuthParams, array('state' => $account_id));
                try {
                        $this->OAuth->finishClientAuthorization(true, $userId, $OAuthParams);
                } catch (OAuth2RedirectException $e) {
                        $e->sendHttpResponse();
                }
        }

        /**
         * Example Login Action
         *
         * Users must authorize themselves before granting the app authorization
         * Allows login state to be maintained after authorization
         *
         */
        public function login() {
                $OAuthParams = $this->OAuth->getAuthorizeParams();                       
                        
                if ($this->request->is('post')) {
                        $this->validateRequest();
                }
                
                if(isset($this->request->query['ip_access'])) {
                        if ($this->Auth->login()) {
                                //Write the auth params to the session for later
                                $this->Session->write('OAuth.params', $OAuthParams);
                                //Remove old auth messages
                                $this->Session->delete('Message.auth');

                                $account_id = null;

                                $this->loadModel('User');
                                if(!empty($currentUser['bundle_id'])) {
                                        $this->User->Bundle->setBundleFilter($currentUser['bundle_id']);
                                }

                                $this->redirect(array('action' => 'authorize', $account_id));
                        } else {
                                $accountlogin = $this->request->here();
                                $accountlogin = str_replace('&ip_access=1', '&oauth_model=account', $accountlogin);
                                $this->redirect($accountlogin);
                        }
                }

                if ($this->request->is('post') && $this->Auth->login()) {
                        //Write the auth params to the session for later
                        $this->Session->write('OAuth.params', $OAuthParams);
                        //Remove old auth messages
                        $this->Session->delete('Message.auth');

                        //Account inheritance
                        $account_id = null;
                        if($this->useAccountsForOAuth())
                        {
                            $currentAccount = $this->Auth->user();
                            @$currentUser = $currentAccount['User'];
                            unset($currentAccount['User']);
                            $currentUser['is_user']=1;
                            $currentUser['account'] = $currentAccount;
                            $account_id = $currentAccount['id'];
                            $this->Session->write('Auth.User', $currentUser);
                        }
                        
                        $this->loadModel('User');
                        if(!empty($currentUser['bundle_id'])) {
                                $this->User->Bundle->setBundleFilter($currentUser['bundle_id']);
                        }
                        $this->redirect(array('action' => 'authorize', $account_id));
                        
                } elseif ($this->request->is('post')) {
                        $this->Session->setFlash(__('Username or password is incorrect'), 'default', array(), 'auth');
                }

                $this->set(compact('OAuthParams'));
        }

        /**
         * Example Token Endpoint - this is where clients can retrieve an access token
         *
         * Grant types and parameters:
         * 1) authorization_code - exchange code for token
         * 	- code
         * 	- client_id
         * 	- client_secret
         *
         * 2) refresh_token - exchange refresh_token for token
         * 	- refresh_token
         * 	- client_id
         * 	- client_secret
         *
         * 3) password - exchange raw details for token
         * 	- username
         * 	- password
         * 	- client_id
         * 	- client_secret
         *
         */
        public function token() {
                $this->autoRender = false;
                try {
                        $this->OAuth->grantAccessToken();
                } catch (OAuth2ServerException $e) {
                        $e->sendHttpResponse();
                }
        }

        /**
         * Blackhold callback
         *
         * OAuth requests will fail postValidation, so rather than disabling it completely
         * if the request does fail this check we store it in $this->blackHoled and then
         * when handling our forms we can use $this->validateRequest() to check if there
         * were any errors and handle them with an exception.
         * Requests that fail for reasons other than postValidation are handled here immediately
         * using the best guess for if it was a form or OAuth
         *
         * @param string $type
         */
        public function blackHole($type) {
                $this->blackHoled = $type;

                if ($type != 'auth') {
                        if (isset($this->request->data['_Token'])) {
                                //Probably our form
                                $this->validateRequest();
                        } else {
                                //Probably OAuth
                                $e = new OAuth2ServerException(OAuth2::HTTP_BAD_REQUEST, OAuth2::ERROR_INVALID_REQUEST, 'Request Invalid.');
                                $e->sendHttpResponse();
                        }
                }
        }

        /**
         * Check for any Security blackhole errors
         *
         * @throws BadRequestException
         */
        private function validateRequest() {
                if ($this->blackHoled) {
                        //Has been blackholed before - naughty
                        throw new BadRequestException(__d('OAuth', 'The request has been black-holed'));
                }
        }
        
}
