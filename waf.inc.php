<?php
include __DIR__ . '/WAF/Firewall';
$waf = new Firewall();
$waf->run();