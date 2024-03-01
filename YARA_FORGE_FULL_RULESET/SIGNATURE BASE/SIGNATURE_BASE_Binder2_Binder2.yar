rule SIGNATURE_BASE_Binder2_Binder2
{
	meta:
		description = "Webshells Auto-generated - file binder2.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "29269dc0-f2e4-56ec-ad64-0dff00e339b7"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L7220-L7236"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d594e90ad23ae0bc0b65b59189c12f11"
		logic_hash = "fbe56b7d37fc7863fcf55761c0b5b671d661a713ac95f90d65b79eee9a447a9b"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "IsCharAlphaNumericA"
		$s2 = "WideCharToM"
		$s4 = "g 5pur+virtu!"
		$s5 = "\\syslog.en"
		$s6 = "heap7'7oqk?not="
		$s8 = "- Kablto in"

	condition:
		all of them
}
