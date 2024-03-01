import "pe"

rule SIGNATURE_BASE_CN_Hacktool_Scanport_Portscanner
{
	meta:
		description = "Detects a chinese Portscanner named ScanPort"
		author = "Florian Roth (Nextron Systems)"
		id = "a708283e-339c-599f-9321-3b063d0076a9"
		date = "2014-12-10"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L636-L650"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "fa2dce57cc3e9baecb80b0165dfeb1af1ba4c4b30098e3b1252eb98b4fc30f7f"
		score = 70
		quality = 60
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "LScanPort" fullword wide
		$s1 = "LScanPort Microsoft" fullword wide
		$s2 = "www.yupsoft.com" fullword wide

	condition:
		all of them
}
