rule SIGNATURE_BASE_Safe0Ver_Shell__Safe_Mod_Bypass_By_Evilc0Der_Php
{
	meta:
		description = "Semi-Auto-generated  - file Safe0ver Shell -Safe Mod Bypass By Evilc0der.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "25971f62-33ee-5ed6-8d72-118be5bd2deb"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L4795-L4807"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "6163b30600f1e80d2bb5afaa753490b6"
		logic_hash = "46f6bb38f1175e02b03047c06a7aed968b1c1ce2e28cc4b88e15703040e91592"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Safe0ver" fullword
		$s1 = "Script Gecisi Tamamlayamadi!"
		$s2 = "document.write(unescape('%3C%68%74%6D%6C%3E%3C%62%6F%64%79%3E%3C%53%43%52%49%50%"

	condition:
		1 of them
}
