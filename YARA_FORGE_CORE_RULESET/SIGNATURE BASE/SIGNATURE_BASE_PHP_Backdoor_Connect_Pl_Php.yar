rule SIGNATURE_BASE_PHP_Backdoor_Connect_Pl_Php
{
	meta:
		description = "Semi-Auto-generated  - file PHP Backdoor Connect.pl.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "96c9258e-3894-5ee9-b52c-eb7ba7454416"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4420-L4432"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "57fcd9560dac244aeaf95fd606621900"
		logic_hash = "b141546f45767884f9c8b1cc4c09ea25f90c0f3a3633bfeecad78b60e7f20306"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "LorD of IRAN HACKERS SABOTAGE"
		$s1 = "LorD-C0d3r-NT"
		$s2 = "echo --==Userinfo==-- ;"

	condition:
		1 of them
}
