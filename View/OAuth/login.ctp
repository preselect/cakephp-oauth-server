<?php
    if(empty($oauth_model))
    {
        $oauth_model = 'User';
    }
    $filter = $this->Session->read('Auth.User.type') == 'COMPANY';
//$filter = true;
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
                echo $this->Form->input('username');
                echo $this->Form->input('password');
                ?>
        </fieldset>
        <?php echo $this->Form->end(__d('portal', 'Login')); ?>
</div>
<?php if($filter): ?>
    <div class="users form shibboleth">
        <?php echo $this->Form->create('Account', array('url' => array('plugin' => false, 'controller' => 'accounts', 'action' => 'register'))); ?>
        <fieldset>
            <legend><?php echo __d('portal', 'Not registered yet? Here you can create your personal user account'); ?></legend>
            <?php
            echo $this->Form->input('first_name');
            echo $this->Form->input('last_name');
            echo $this->Form->input('email');
            echo $this->Form->input('password');
            ?>

        </fieldset>
        <?php echo $this->Form->end(__d('portal', 'Register')); ?>
    </div>
<?php endif; ?>

<div class="clearBoth"></div>