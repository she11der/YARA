rule SIGNATURE_BASE_FSO_S_Tool
{
	meta:
		description = "Webshells Auto-generated - file tool.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "ed744aa4-7a35-57d6-89bd-3286a21b50a0"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L7957-L7968"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3a1e1e889fdd974a130a6a767b42655b"
		logic_hash = "a3449aca3124aa4d920d78e5e674ddd9d8a181b0ce0143032352a69dfdbcad2d"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s7 = "\"\"%windir%\\\\calc.exe\"\")"

	condition:
		all of them
}
