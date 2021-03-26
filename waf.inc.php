<?php
include_once dirname(__FILE__) . '/WAF/Firewall.php';
$waf = new Firewall();
$waf->run();
