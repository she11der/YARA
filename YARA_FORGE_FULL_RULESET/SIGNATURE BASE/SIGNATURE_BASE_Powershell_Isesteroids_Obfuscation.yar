rule SIGNATURE_BASE_Powershell_Isesteroids_Obfuscation
{
	meta:
		description = "Detects PowerShell ISESteroids obfuscation"
		author = "Florian Roth (Nextron Systems)"
		id = "d686c4de-28fd-5d77-91d4-dde5661b75cd"
		date = "2017-06-23"
		modified = "2023-12-05"
		reference = "https://twitter.com/danielhbohannon/status/877953970437844993"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_obfuscation.yar#L11-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6d9476f679614e34a0d13664baffd15b0bdb896f7eeca2c9de66bdc0d65a2eec"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "/\\/===\\__" ascii
		$x2 = "${__/\\/==" ascii
		$x3 = "Catch { }" fullword ascii
		$x4 = "\\_/=} ${_" ascii

	condition:
		2 of them
}
