rule SIGNATURE_BASE_Sh_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "da691516-d6c9-5c4b-85c3-f1cd7fc96ae7"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4679-L4690"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "330af9337ae51d0bac175ba7076d6299"
		logic_hash = "b0c3307d451e5d7dadece114e2888503a46038e2edb2ff32bf566ce47b300e76"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "$ar_file=array('/etc/passwd','/etc/shadow','/etc/master.passwd','/etc/fstab','/e"
		$s2 = "Show <input type=text size=5 value=\".((isset($_POST['br_st']))?$_POST['br_st']:"

	condition:
		1 of them
}