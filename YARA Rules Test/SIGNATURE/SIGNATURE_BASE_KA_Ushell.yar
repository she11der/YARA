rule SIGNATURE_BASE_KA_Ushell
{
	meta:
		description = "Webshells Auto-generated - file KA_uShell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "34e220db-2fb5-59dc-b5e8-d88f844d3977"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7404-L7416"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "685f5d4f7f6751eaefc2695071569aab"
		logic_hash = "58d25e19e2e14a909b4b623a85dfd8c62974121d3b23574d1e94b62385e42b45"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass"
		$s6 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}"

	condition:
		all of them
}