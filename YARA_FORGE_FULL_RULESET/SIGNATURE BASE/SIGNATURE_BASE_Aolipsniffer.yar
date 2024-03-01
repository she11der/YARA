import "pe"

rule SIGNATURE_BASE_Aolipsniffer
{
	meta:
		description = "Auto-generated rule on file aolipsniffer.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "f7cc0f31-6ba4-504b-82de-0334257b8a95"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L314-L332"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "51565754ea43d2d57b712d9f0a3e62b8"
		logic_hash = "e627b8ea85e4325714c98e93ad6147adfa600af548a80dce8548b7f5743733b5"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB"
		$s1 = "dwGetAddressForObject"
		$s2 = "Color Transfer Settings"
		$s3 = "FX Global Lighting Angle"
		$s4 = "Version compatibility info"
		$s5 = "New Windows Thumbnail"
		$s6 = "Layer ID Generator Base"
		$s7 = "Color Halftone Settings"
		$s8 = "C:\\WINDOWS\\SYSTEM\\MSWINSCK.oca"

	condition:
		all of them
}
