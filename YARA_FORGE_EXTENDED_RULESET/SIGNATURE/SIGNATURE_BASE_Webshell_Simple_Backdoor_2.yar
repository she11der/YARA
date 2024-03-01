rule SIGNATURE_BASE_Webshell_Simple_Backdoor_2
{
	meta:
		description = "PHP Webshells Github Archive - file simple-backdoor.php"
		author = "Florian Roth (Nextron Systems)"
		id = "faddd38e-d0c6-5299-9983-53351af1ece5"
		date = "2023-12-05"
		modified = "2023-12-05"
		old_rule_name = "WebShell_simple_backdoor"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6071-L6091"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "edcd5157a68fa00723a506ca86d6cbb8884ef512"
		logic_hash = "655e445e51ec0f1bdce006a72acf3bce95941a349c279c14768760fa9f6f9d76"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
		$s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
		$s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
		$s3 = "        echo \"</pre>\";" fullword
		$s4 = "        $cmd = ($_REQUEST['cmd']);" fullword
		$s5 = "        echo \"<pre>\";" fullword
		$s6 = "if(isset($_REQUEST['cmd'])){" fullword
		$s7 = "        die;" fullword
		$s8 = "        system($cmd);" fullword

	condition:
		all of them
}
