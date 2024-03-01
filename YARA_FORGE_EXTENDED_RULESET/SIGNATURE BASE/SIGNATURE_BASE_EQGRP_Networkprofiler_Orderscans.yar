import "pe"

rule SIGNATURE_BASE_EQGRP_Networkprofiler_Orderscans
{
	meta:
		description = "EQGRP Toolset Firewall - file networkProfiler_orderScans.sh"
		author = "Florian Roth (Nextron Systems)"
		id = "2d48df0c-f950-5bb6-8d3e-77c2f970eb57"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L369-L383"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0cdf4f3d8f668ce5d5aab652c83cb4d2a9acc3471ff720448d021707b34402ef"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ea986ddee09352f342ac160e805312e3a901e58d2beddf79cd421443ba8c9898"

	strings:
		$x1 = "Unable to save off predefinedScans directory" fullword ascii
		$x2 = "Re-orders the networkProfiler scans so they show up in order in the LP" fullword ascii

	condition:
		1 of them
}
