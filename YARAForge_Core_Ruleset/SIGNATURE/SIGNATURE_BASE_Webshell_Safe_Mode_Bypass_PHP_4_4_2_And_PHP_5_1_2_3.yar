rule SIGNATURE_BASE_Webshell_Safe_Mode_Bypass_PHP_4_4_2_And_PHP_5_1_2_3
{
	meta:
		description = "PHP Webshells Github Archive - file Safe_Mode_Bypass_PHP_4.4.2_and_PHP_5.1.2.php"
		author = "Florian Roth (Nextron Systems)"
		id = "349cf6ac-92b3-59f7-a6e4-c23e69b454c6"
		date = "2023-12-05"
		modified = "2023-12-05"
		old_rule_name = "WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5809-L5826"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "db076b7c80d2a5279cab2578aa19cb18aea92832"
		logic_hash = "6840af0d9f99277277edce93deb54e9a319c8938169701c89fdeb65207590951"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>" fullword
		$s6 = "by PHP Emperor<xb5@hotmail.com>" fullword
		$s9 = "\".htmlspecialchars($file).\" has been already loaded. PHP Emperor <xb5@hotmail."
		$s11 = "die(\"<FONT COLOR=\\\"RED\\\"><CENTER>Sorry... File" fullword
		$s15 = "if(empty($_GET['file'])){" fullword
		$s16 = "echo \"<head><title>Safe Mode Shell</title></head>\"; " fullword

	condition:
		3 of them
}