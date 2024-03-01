rule SIGNATURE_BASE_Webshell_Qsd_Php_Backdoor
{
	meta:
		description = "PHP Webshells Github Archive - file qsd-php-backdoor.php"
		author = "Florian Roth (Nextron Systems)"
		id = "f8208851-159c-5d0b-91ad-478aeb4fc9fd"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L6358-L6372"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "4856bce45fc5b3f938d8125f7cdd35a8bbae380f"
		logic_hash = "3ef7b67cd60370a99fdfa6fd614f71ee314af27c9d983383dde8f03a127a28b3"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "// A robust backdoor script made by Daniel Berliner - http://www.qsdconsulting.c"
		$s2 = "if(isset($_POST[\"newcontent\"]))" fullword
		$s3 = "foreach($parts as $val)//Assemble the path back together" fullword
		$s7 = "$_POST[\"newcontent\"]=urldecode(base64_decode($_POST[\"newcontent\"]));" fullword

	condition:
		2 of them
}
