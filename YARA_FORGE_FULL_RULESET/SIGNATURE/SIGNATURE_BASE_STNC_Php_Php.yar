rule SIGNATURE_BASE_STNC_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file STNC.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "8a7167f6-fa62-574f-a37c-3ceadc7f92ec"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4078-L4091"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2e56cfd5b5014cbbf1c1e3f082531815"
		logic_hash = "b4118dc45ac109bde1cafda24cc103370db57c1993690f450cff828c1633af3c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "drmist.ru" fullword
		$s1 = "hidden(\"action\",\"download\").hidden_pwd().\"<center><table><tr><td width=80"
		$s2 = "STNC WebShell"
		$s3 = "http://www.security-teams.net/index.php?showtopic="

	condition:
		1 of them
}
