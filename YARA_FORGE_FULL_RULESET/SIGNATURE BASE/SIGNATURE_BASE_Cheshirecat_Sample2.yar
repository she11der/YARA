rule SIGNATURE_BASE_Cheshirecat_Sample2 : FILE
{
	meta:
		description = "Auto-generated rule"
		author = "Florian Roth (Nextron Systems)"
		id = "14448138-0af3-5669-8aa3-f9e773e2a008"
		date = "2015-08-08"
		modified = "2023-12-05"
		reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_cheshirecat.yar#L11-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "dc18850d065ff6a8364421a9c8f9dd5fcce6c7567f4881466cee00e5cd0c7aa8"
		logic_hash = "4dd299cfe36545dba5ccac22d2eedc405f548fe5f976514d1cfa8238b472782c"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "mpgvwr32.dll" fullword ascii
		$s1 = "Unexpected failure of wait! (%d)" fullword ascii
		$s2 = "\"%s\" /e%d /p%s" fullword ascii
		$s4 = "error in params!" fullword ascii
		$s5 = "sscanf" fullword ascii
		$s6 = "<>Param : 0x%x" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 4 of ($s*)
}
