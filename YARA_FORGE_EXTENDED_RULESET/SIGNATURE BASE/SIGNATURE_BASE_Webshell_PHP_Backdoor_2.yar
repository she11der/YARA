rule SIGNATURE_BASE_Webshell_PHP_Backdoor_2
{
	meta:
		description = "PHP Webshells Github Archive - file php-backdoor.php"
		author = "Florian Roth (Nextron Systems)"
		id = "65e1305b-4fc7-5885-b3df-92846bb57fe3"
		date = "2023-12-05"
		modified = "2023-12-05"
		old_rule_name = "WebShell_php_backdoor"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L5844-L5860"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b190c03af4f3fb52adc20eb0f5d4d151020c74fe"
		logic_hash = "4228bcbfff5d7756615347196270f7916843e2aceacc7298610070b8b923381b"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=/etc on *nix" fullword
		$s6 = "// a simple php backdoor | coded by z0mbie [30.08.03] | http://freenet.am/~zombi"
		$s11 = "if(!isset($_REQUEST['dir'])) die('hey,specify directory!');" fullword
		$s13 = "else echo \"<a href='$PHP_SELF?f=$d/$dir'><font color=black>\";" fullword
		$s15 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input "

	condition:
		1 of them
}
