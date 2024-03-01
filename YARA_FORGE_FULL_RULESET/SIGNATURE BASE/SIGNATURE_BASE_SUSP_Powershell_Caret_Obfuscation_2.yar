rule SIGNATURE_BASE_SUSP_Powershell_Caret_Obfuscation_2
{
	meta:
		description = "Detects powershell keyword obfuscated with carets"
		author = "Florian Roth (Nextron Systems)"
		id = "976e261a-029c-5703-835f-a235c5657471"
		date = "2019-07-20"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_obfuscation.yar#L43-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0aa21df64d61cb299b0f77da8b97e8cfc379622a8092e71657c478519d83fd31"
		score = 65
		quality = 31
		tags = ""

	strings:
		$r1 = /p[\^]?o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l\^l/ ascii wide nocase fullword
		$r2 = /p\^o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l[\^]?l/ ascii wide nocase fullword

	condition:
		1 of them
}
