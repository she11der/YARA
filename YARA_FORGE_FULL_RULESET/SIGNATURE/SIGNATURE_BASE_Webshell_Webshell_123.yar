rule SIGNATURE_BASE_Webshell_Webshell_123
{
	meta:
		description = "Web shells - generated from file webshell-123.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-01-27"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3331-L3348"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2782bb170acaed3829ea9a04f0ac7218"
		logic_hash = "1caccadf2bd7d265f9b5026c82acc31ade95313d57382651004db8b5e361312d"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "// Web Shell!!" fullword
		$s1 = "@preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6"
		$s3 = "$default_charset = \"UTF-8\";" fullword
		$s4 = "// url:http://www.weigongkai.com/shell/"

	condition:
		2 of them
}
