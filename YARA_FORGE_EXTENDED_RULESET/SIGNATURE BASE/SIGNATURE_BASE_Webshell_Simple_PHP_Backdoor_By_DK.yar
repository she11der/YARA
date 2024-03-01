rule SIGNATURE_BASE_Webshell_Simple_PHP_Backdoor_By_DK
{
	meta:
		description = "PHP Webshells Github Archive - file Simple_PHP_backdoor_by_DK.php"
		author = "Florian Roth (Nextron Systems)"
		id = "2c424714-1d2c-5b89-b1bc-a201e37a0a5d"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6139-L6154"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "03f6215548ed370bec0332199be7c4f68105274e"
		logic_hash = "1f65f759ec4045c521085aad84d0aea4dcfcf26eac4357751cf1dde6886d1718"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
		$s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
		$s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
		$s6 = "if(isset($_REQUEST['cmd'])){" fullword
		$s8 = "system($cmd);" fullword

	condition:
		2 of them
}
