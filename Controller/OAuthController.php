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
                
                if (isset($this->request->query['subscription'])&& isset($this->request->query['hash'])) {
                    $external_api_url = $this->Session->read('Filter.external_api_url');
                    $external_api_key = $this->Session->read('Filter.external_api_key');                    
                    $subscription = $this->request->query['subscription'];
                    $hash = md5($subscription . $external_api_key);
                    
                    if ($hash <> $this->request->query['hash']) {
                        throw new NotFoundException(__('Invalid hash'));
                        }
                    
                    if (!$this->validateSubscription($subscription, $external_api_url, $external_api_key)) {
                        $this->Session->setFlash(__('Expired ') . $this->Session->read('Filter.label_subscription'));
                        $this->Session->delete('Auth');
                        $accountlogin = $this->request->here();
                        $this->redirect($accountlogin);
                        }
                }
                
                if (isset($this->request->query['token'])) {
                    $external_api_url = $this->Session->read('Filter.external_api_url');
                    $bundle_id = $this->Session->read('Filter.id');
                    $token = $this->request->query['token'];
                    $external_account_details = $this->validateToken($token, $external_api_url);
                    if (!$external_account_details) {
                        $this->Session->setFlash(__('Invalid token'));
                        } else {
                            $this->Session->write('OAuth.params', $OAuthParams);
                            // get main User via bundle user_id
                            $this->loadModel('User');
                            $user = $this->User->findByBundleId($bundle_id);
                            // debug($user);
                            $user_id = $user['User']['id'];
                            // get account if already exists
                            $this->loadModel('Account');
                            $account = $this->Account->findByUsername($external_account_details['email']);
                            if(empty($account)) {
                                // Create account & login
                                $this->Account->create();
                                $account['Account']['user_id'] = $user_id;
                                $account['Account']['active'] = 1;
                                $account['Account']['password'] = md5($external_account_details['userid']);
                                $account['Account']['username'] = $external_account_details['email'];
                                $account['Account']['email'] = $external_account_details['email'];
                                $account['Account']['first_name'] = $external_account_details['vorname'];
                                $account['Account']['last_name'] = $external_account_details['name'];
                                $account['Account']['subscription'] = $external_account_details['userid'];
                                if ($this->Account->save($account)) {
                                        $currentUser = $user['User'];
                                        $currentAccount = $this->Account->read(null, $this->Account->getLastInsertID());
                                        $currentUser['is_user'] = 1;
                                        $currentUser['account'] = $currentAccount['Account'];
                                        unset($currentUser['account']['password']);
                                        if (!empty($currentUser['bundle_id'])) {
                                                $this->User->Bundle->setBundleFilter($currentUser['bundle_id']);
                                        }
                                        $this->Session->write('Auth.User', $currentUser);
                                        $this->redirect(array('action' => 'authorize', $currentUser['account']['id']));
                                }
                            } else {
                                // autologin    
                                $currentUser = $user['User'];
                                $currentAccount = $account;
                                $currentUser['is_user'] = 1;
                                $currentUser['account'] = $currentAccount['Account'];
                                unset($currentUser['account']['password']);
                                if (!empty($currentUser['bundle_id'])) {
                                        $this->User->Bundle->setBundleFilter($currentUser['bundle_id']);
                                }
                                $this->Session->write('Auth.User', $currentUser);
                                $this->redirect(array('action' => 'authorize', $currentUser['account']['id']));
                            }
                        }
                }                
                
                if ($this->request->is('post')) {
                        $this->validateRequest();
                }

                if (isset($this->request->query['account_id'])) {
                        $id = $this->request->query['account_id'];
                        $this->loadModel('Account');
                        if (!$this->Account->exists($id)) {
                                throw new NotFoundException(__('Invalid account'));
                        } else {
                                $this->Account->id = $id;
                                $this->Account->saveField('active', true);
                                $this->Session->setFlash(__('Registration was sucesful. You can now login with your new account'));
                        }
                }

                if (isset($this->request->query['ip_access'])) {
                        if ($this->Auth->login()) {
                                //Write the auth params to the session for later
                                $this->Session->write('OAuth.params', $OAuthParams);
                                //Remove old auth messages
                                $this->Session->delete('Message.auth');

                                $account_id = null;

                                $this->loadModel('User');
                                if (!empty($currentUser['bundle_id'])) {
                                        $this->User->Bundle->setBundleFilter($currentUser['bundle_id']);
                                }

                                $this->redirect(array('action' => 'authorize', $account_id));
                        } else {
                                $accountlogin = $this->request->here();
                                $accountlogin = str_replace('&ip_access=1', '&oauth_model=account', $accountlogin);
                                $this->redirect($accountlogin);
                        }
                }

                if (isset($this->request->query['authcode'])) {
                        if ($this->Auth->login()) {
                                //Write the auth params to the session for later
                                $this->Session->write('OAuth.params', $OAuthParams);
                                //Remove old auth messages
                                $this->Session->delete('Message.auth');

                                $account_id = null;

                                $this->loadModel('User');
                                if (!empty($currentUser['bundle_id'])) {
                                        $this->User->Bundle->setBundleFilter($currentUser['bundle_id']);
                                }
                                if (isset($this->request->query['start'])) {
                                        $this->redirect(array('action' => 'authorize', $account_id));
                                }
                                $registerquery = $this->request->here();
                                $registerquery = str_replace('&authcode', '&authcode_temp', $registerquery);
                                $registerquery .= '&oauth_model=account';
                                $this->redirect($registerquery);
                        } else {
                                $this->Session->setFlash(__('No access'), 'default', array(), 'auth');
                        }
                }

                if ($this->request->is('post') && $this->Auth->login()) {
                        //Write the auth params to the session for later
                        $this->Session->write('OAuth.params', $OAuthParams);
                        //Remove old auth messages
                        $this->Session->delete('Message.auth');

                        //Account inheritance
                        $account_id = null;
                        if ($this->useAccountsForOAuth()) {
                                $currentAccount = $this->Auth->user();
                                @$currentUser = $currentAccount['User'];
                                unset($currentAccount['User']);
                                $currentUser['is_user'] = 1;
                                $currentUser['account'] = $currentAccount;
                                $account_id = $currentAccount['id'];
                                $account_subscription = $currentAccount['subscription'];
                                
                                if(($currentUser['force_subscription'])) {

                                    // Check ob expired
                                    $account_subscription = $currentAccount['subscription'];
                                    $external_api_url = $this->Session->read('Filter.external_api_url');
                                    $external_api_key = $this->Session->read('Filter.external_api_key');

                                    if (!$this->validateSubscription($account_subscription, $external_api_url, $external_api_key)) {
                                            $this->Session->setFlash($this->Session->read('Filter.label_message_expired'));
                                            $this->Session->delete('Filter');
                                            $this->Session->delete('Auth');
                                            $referer = str_replace('&account_id=', '&account_id_temp=', $this->referer());
                                            return $this->redirect($referer);
                                    }                                    
                                    
                                }

                                $this->Session->write('Auth.User', $currentUser);
                        }

                        $this->loadModel('User');
                        if (!empty($currentUser['bundle_id'])) {
                                $this->User->Bundle->setBundleFilter($currentUser['bundle_id']);
                        }
                        $this->redirect(array('action' => 'authorize', $account_id));
                } elseif ($this->request->is('post')) {
                        $this->Session->setFlash(__('Username or password is incorrect'), 'default', array(), 'auth');
                }

                $this->set(compact('OAuthParams', 'subscription'));
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

        private function validateSubscription($subscription, $external_api_url, $external_api_key) {
                $hash = md5($subscription . $external_api_key);
                $url = $external_api_url . $subscription . '&hash=' . $hash;
                $get_validation = file_get_contents($url);
                $get_validation = json_decode($get_validation);
                if ($get_validation->status_code == '1') {
                        $validation = true;
                } else {
                        $validation = false;
                }
                return $validation;
        }

        private function validateToken($token, $external_api_url) {
                $url = $external_api_url . $token;
                $get_validation = file_get_contents($url);
                $get_validation = json_decode($get_validation);
                if ($get_validation->status == 'OK') {
                        $account_details = (array) $get_validation;
                        return $account_details;
                } else {
                        return false;
                }
        }        
        
}
