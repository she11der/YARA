rule SIGNATURE_BASE_Projectm_Darkcomet_1 : FILE
{
	meta:
		description = "Detects ProjectM Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "6de74d73-f9b2-5e7f-b15e-f850425d849c"
		date = "2016-03-26"
		modified = "2023-01-27"
		reference = "http://researchcenter.paloaltonetworks.com/2016/03/unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_project_m.yar#L10-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "cc488690ce442e9f98bac651218f4075ca36c355d8cd83f7a9f5230970d24157"
		logic_hash = "81ffaa382bb6f817fe2917a096a3eee49d2e8c281271da551ccd65679692712f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "DarkO\\_2" fullword ascii
		$a1 = "AVICAP32.DLL" fullword ascii
		$a2 = "IDispatch4" fullword ascii
		$a3 = "FLOOD/" fullword ascii
		$a4 = "T<-/HTTP://" ascii
		$a5 = "infoes" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 4 of them ) or ( all of them )
}
