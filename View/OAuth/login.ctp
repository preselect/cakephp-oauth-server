<style>
        .checkbox {
                padding: 5px;
                font-size: small;
        }
</style>

<?php
if (empty($oauth_model)) {
        $oauth_model = 'User';
}
$filter = ($this->Session->read('Auth.User.type') == 'COMPANY' OR $this->Session->read('Auth.User.type') == 'LIMITED') && $this->request->query['oauth_model'] == 'account';

if (isset($this->request->query['mailadresse'])) {
        $email = urldecode($this->request->query['mailadresse']);
} else {
        $email = '';
}

?>
<div class="users form <?php echo $filter ? 'login' : 'filter_login'; ?>">
<?php echo $this->Session->flash('auth'); ?>
        <?php echo $this->Form->create($oauth_model); ?>
        <fieldset>
                <legend><?php echo __d('portal', 'Please enter your username and password'); ?></legend>
<?php
foreach ($OAuthParams as $key => $value) {
        echo $this->Form->hidden(h($key), array('value' => h($value)));
}
?>
                <?php
                echo $this->Form->input('username', array('label' => __d('portal', 'Username'), 'default' => $email));
                echo $this->Form->input('password', array('label' => __d('portal', 'Password')));
                ?>
        </fieldset>
                <?php echo $this->Form->end(__d('portal', 'Login')); ?>
        <?php if ($this->request->query['oauth_model'] == 'account'): ?>
                <div class="noAccess"><?php echo $this->Html->link(__d('portal', 'Password forgotten'), '/accounts/password_reset'); ?></div>
        <?php endif; ?>
</div>
        <?php if ($filter): ?>
        <div class="users form shibboleth">
        <?php echo $this->Form->create('Account', array('url' => array('plugin' => false, 'controller' => 'accounts', 'action' => 'register', 'autologin' => 'false'))); ?>
                <fieldset>
                        <legend><?php echo __d('portal', 'Not registered yet? Here you can create your personal user account'); ?></legend>
        <?php
        echo $this->Form->input('first_name', array('label' => __d('portal', 'First Name')));
        echo $this->Form->input('last_name', array('label' => __d('portal', 'Last Name')));
        if ($this->Session->read('Filter.external_api_url') <> '') { 
                if(isset($subscription)) {
                       echo $this->Form->input('subscription_disabled', array('label' => $this->Session->read('Filter.label_subscription'), 'default' => $subscription, 'disabled'=> 'disabled'));
                       echo $this->Form->input('subscription', array('type' => 'hidden', 'default' => $subscription));  
                } else {
                       echo $this->Form->input('subscription', array('label' => $this->Session->read('Filter.label_subscription'), 'required' => true));                               
                }
        }        
        echo $this->Form->input('email', array('label' => __d('portal', 'Email'), 'default' => $email));
        echo $this->Form->input('password', array('label' => __d('portal', 'Password')));
        if ($this->Session->read('Filter.terms_text') <> '') {
        echo $this->Form->input('agreed', array('div' => false,
            'label' => false,
            'type' => 'checkbox',
            'required' => true,
            'before' => '<label class="checkbox">',
        'after' => 'Ich habe die <a href="' . $this->request->here() . '&showterms=1' . '">Nutzungsbedingungen</a> gelesen und akzeptiere diese.</label>'
        ));
        }
        ?>

                </fieldset>
                        <?php echo $this->Form->end(__d('portal', 'Register')); ?>
        </div>
        <?php endif; ?>

<div class="clearBoth"></div>
<br><br>

<?php
if(isset($this->request->query['showterms'])) {

?>
<div id="wrapperContent">
        <div id="content" class="width">
                <div id="headContent">
                </div>
                <div id="mainContent">
                        <div class="fullsize"><h1>Nutzungsbedingungen</h1></div>
                                <div class="large">
                                <?php echo $this->Session->read('Filter.terms_text'); ?>
                                </div>
                        
                </div>
        </div>
</div>
<?php } ?>