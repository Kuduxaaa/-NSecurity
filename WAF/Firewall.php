<?php

/**
 * @author Kuduxaaa <nikakuduxashvili0@gmail.com>
 * @package Framework\Firewall
 * Powered By NSS 🛡️
*/

require_once __DIR__ . '/Core/Denylist.php';

class Firewall {

    /**
     * Available filters and their default status
     *
     * @var array
     */

	private $protections = array(
		'TOR' => true,
		'SQLi' => true,
		'XSS' => true,
		'LFI' => true,
		'RFI' => true,
		'RCE' => true,
		'Bots' => true,
	);

	private $log_file = 'attacks.log';
	private $logging = true;
	private $params;
	private $deny;

	public function __construct()
	{
		@header("X-Powered-By: NSec");
		@header("X-XSS-Protection: 1; mode=block");
		$this->deny = new Denylist();
		$this->params = array_map(function($elem){
			return strtolower($elem);
		}, array_merge($_GET, $_POST, $_COOKIE, $_REQUEST));
	}


    /**
     * Render error page with HTTP status code 400
     */

	public function renderError (int $code, string $reason): self
	{
		http_response_code((int) $code);
		echo "$code -> $reason";
		if ($this->logging)
		{
			$this->log($reason);
		}

		exit;
	}


    /**
     * Write the detected to a log file
     *
     * @param string $attack_type
     * @return Firewall
     */

	private function log (string $attack_type): self
	{
		if (!empty($this->log_file) && !empty($this->log_format))
		{
			$file_loc = dirname(__FILE__) . '/Logs/' . $this->log_file;
			$data = date('Y-m-d H:i:s') . "($_SERVER[REMOTE_ADDR]) [$attack_type] - $_SERVER[REQUEST_URI]";
			
			file_put_contents($file_loc, "\n$data", FILE_APPEND);
		}

		return $this;
	}



    /**
     * Check if the params contains forbidden characters
     *
     * @param string $arr
     * @param string $reason
     * @return Firewall
     */

	public function check(array $arr, string $reason='Error'): self
	{
		if (is_array($arr))
		{
			foreach ($this->params as $param) {
				$temp = str_replace($arr, '~#1NF1CI3D', $param);
				if (strrpos($temp, '~#1NF1CI3D'))
				{
					$this->renderError(400, $reason);
				}
			}
		}

		return $this;
	}


    /**
     * Check if the params contains forbidden characters
     *
     * @param string $attack_type
     * @return Firewall
     */

	public function blockBadBots(array $arr)
	{
		$userAgent = $_SERVER['HTTP_USER_AGENT'];
		if (is_array($arr))
		{
			$temp = str_replace($arr, '~#1NF1CI3D', $userAgent);
			if (strpos($temp, '~#1NF1CI3D') !== false)
			{
				$this->log('BadBot');
				die('[IDITE NAXUI]');
			}
		}
	}


    /**
     * TOR Traffic detector
     */

	public function detectTor()
	{
		$client_ip = $_SERVER['REMOTE_ADDR'];
		$temp_ip = str_replace($this->deny::$tor, '~#1NF1CI3D', $client_ip);
		if ($temp_ip !== $client_ip)
		{
			$this->renderError(400, 'TOR');
		}
	}


    /**
     * Enable a given filter
     *
     * @param string $filter
     * @return boolean
     */

	public function enableFilter (string $filter): bool
	{
		if (!$this->protections[$filter])
		{
			$this->protections[$filter] = true;
			return true;
		}
		else
		{
			return false;
		}
	}


    /**
     * Set log file path
     *
     * @param string $value
     * @return boolean
     */
    public function setLogFile(string $value): bool
    {
    	if (!$this->logging)
    	{
    		$this->setLogging(true); // Auto start logging mode if it disabled
    	}

        $this->log_file = $value;

        return true;
    }


    /**
     * Set logging mode
     *
     * @param bool $value
     * @return boolean
     */
    public function setLogging(bool $mode): bool
    {
        $this->logging = $mode;

        return true;
    }


    /**
     * Disable a given filter
     *
     * @param string $filter
     * @return boolean
     */

	public function disableFilter (string $filter): bool
	{
		if (!$this->protections[$filter])
		{
			$this->protections[$filter] = false;
			return true;
		}
		else
		{
			return false;
		}
	}


    /**
     * Runs all the enabled filters
     *
     * @return Firewall
     */

	public function run(): self
	{
		if (strlen($_SERVER['REQUEST_URI']) > 2000)
		{
			$this->renderError(400, 'Too long URL');
		}

		if ($this->protections['TOR'])
		{
			$this->detectTor();
		}

		if ($this->protections['SQLi'])
		{
			$this->check($this->deny::$sql, 'SQL Injection');
		}

		if ($this->protections['XSS'])
		{
			$this->check($this->deny::$xss, 'XSS Attemp');
		}

		if ($this->protections['LFI'])
		{
			$this->check($this->deny::$lfi, 'LFI Attemp');
		}

		if ($this->protections['RFI'])
		{
			$this->check($this->deny::$rfi, 'RFI Attemp');
		}

		if ($this->protections['RCE'])
		{
			$this->check($this->deny::$rce, 'RCE Attemp');
		}

		if ($this->protections['Bots'])
		{
			$this->blockBadBots($this->deny::$bot);
		}

		return $this;
	}


    /**
     * Get list with filters
     *
     * @return array
     */

	public function getFilters(): array
    {
        return $this->protections;
    }
}
