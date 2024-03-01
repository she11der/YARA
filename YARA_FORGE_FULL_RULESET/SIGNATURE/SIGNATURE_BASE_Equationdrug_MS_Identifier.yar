import "pe"

rule SIGNATURE_BASE_Equationdrug_MS_Identifier
{
	meta:
		description = "Microsoft Identifier used in EquationDrug Platform"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		id = "c934c117-bf5a-5688-acd9-5d6c6aacd6bc"
		date = "2015-03-11"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1937-L1948"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7b919c82b6e765be5adb927bf79d13f9b37a214a6f8a1f7b237a88ba46ae958c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "Microsoft(R) Windows (TM) Operating System" fullword wide

	condition:
		$s1 and pe.timestamp>946684800
}
