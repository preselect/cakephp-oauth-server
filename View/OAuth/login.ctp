<div class="users form">
        <?php echo $this->Session->flash('auth'); ?>
        <?php echo $this->Form->create('User'); ?>
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
