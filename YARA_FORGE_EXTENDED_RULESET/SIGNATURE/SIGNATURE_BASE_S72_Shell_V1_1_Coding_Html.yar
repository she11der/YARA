rule SIGNATURE_BASE_S72_Shell_V1_1_Coding_Html
{
	meta:
		description = "Semi-Auto-generated  - file s72 Shell v1.1 Coding.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "dfd3b80e-6245-5f74-9d6a-6006218891ac"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L4393-L4405"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c2e8346a5515c81797af36e7e4a3828e"
		logic_hash = "aef8840b72e5c435c11150007d6b3af2943126fefdc6df343d0f73755340e260"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Dizin</font></b></font><font face=\"Verdana\" style=\"font-size: 8pt\"><"
		$s1 = "s72 Shell v1.0 Codinf by Cr@zy_King"
		$s3 = "echo \"<p align=center>Dosya Zaten Bulunuyor</p>\""

	condition:
		1 of them
}
