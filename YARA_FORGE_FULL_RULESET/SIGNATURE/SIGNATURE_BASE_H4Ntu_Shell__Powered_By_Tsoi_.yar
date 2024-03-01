rule SIGNATURE_BASE_H4Ntu_Shell__Powered_By_Tsoi_
{
	meta:
		description = "Semi-Auto-generated  - file h4ntu shell [powered by tsoi].txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "186358e6-88a3-5fad-b1ba-a49b2a5dea1c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4889-L4900"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "06ed0b2398f8096f1bebf092d0526137"
		logic_hash = "32c620a4ed3f7a8640928e2211516978c12cfbdedb7d96e923303740407b5a1c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "h4ntu shell"
		$s1 = "system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\");"

	condition:
		1 of them
}
