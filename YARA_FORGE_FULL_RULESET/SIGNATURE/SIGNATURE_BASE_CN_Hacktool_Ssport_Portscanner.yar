import "pe"

rule SIGNATURE_BASE_CN_Hacktool_Ssport_Portscanner
{
	meta:
		description = "Detects a chinese Portscanner named SSPort"
		author = "Florian Roth (Nextron Systems)"
		id = "38cc8830-efd3-51b7-8ac6-c9bf468212cb"
		date = "2014-12-10"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L620-L634"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "30c380b6c683cbcbef7072e793d94e1782206b844fa23d334b737818f0a32f9f"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Golden Fox" fullword wide
		$s1 = "Syn Scan Port" fullword wide
		$s2 = "CZ88.NET" fullword wide

	condition:
		all of them
}
