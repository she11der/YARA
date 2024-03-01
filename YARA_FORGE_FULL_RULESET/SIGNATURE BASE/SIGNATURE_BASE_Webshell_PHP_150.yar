rule SIGNATURE_BASE_Webshell_PHP_150
{
	meta:
		description = "Web Shell - file 150.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1741-L1755"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "400c4b0bed5c90f048398e1d268ce4dc"
		logic_hash = "139e3d6aa3cd2b6a9731a6cc14c921f9fd82ff7ca79d156f1ff6bc544897fb12"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "HJ3HjqxclkZfp"
		$s1 = "<? eval(gzinflate(base64_decode('" fullword

	condition:
		all of them
}
