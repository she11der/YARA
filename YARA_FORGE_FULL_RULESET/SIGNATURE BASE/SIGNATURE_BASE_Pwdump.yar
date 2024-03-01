import "pe"

rule SIGNATURE_BASE_Pwdump
{
	meta:
		description = "PwDump 6 variant"
		author = "Marc Stroebel"
		id = "e557e548-53e8-5098-93d4-8e899384e67c"
		date = "2014-04-24"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L58-L72"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a998d16f84e8689f182f6665ad165c6ff19e25d3e52acc10ca4cc6fe54ba354f"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s5 = "Usage: %s [-x][-n][-h][-o output_file][-u user][-p password][-s share] machineNa"
		$s6 = "Unable to query service status. Something is wrong, please manually check the st"
		$s7 = "pwdump6 Version %s by fizzgig and the mighty group at foofus.net" fullword

	condition:
		1 of them
}
