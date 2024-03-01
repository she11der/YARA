rule SIGNATURE_BASE_Zehir_4_Asp
{
	meta:
		description = "Semi-Auto-generated  - file Zehir 4.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "ea7df4e1-d4e2-5a58-a014-d12cb9afaf79"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4667-L4678"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "7f4e12e159360743ec016273c3b9108c"
		logic_hash = "69063d866daf1709df81fa22d76177bf8d552e19725a94db4a1b2fca79387faf"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s2 = "</a><a href='\"&dosyapath&\"?status=10&dPath=\"&f1.path&\"&path=\"&path&\"&Time="
		$s4 = "<input type=submit value=\"Test Et!\" onclick=\""

	condition:
		1 of them
}
