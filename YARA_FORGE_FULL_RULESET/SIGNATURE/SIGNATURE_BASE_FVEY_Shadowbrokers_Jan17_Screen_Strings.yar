rule SIGNATURE_BASE_FVEY_Shadowbrokers_Jan17_Screen_Strings : FILE
{
	meta:
		description = "Detects strings derived from the ShadowBroker's leak of Windows tools/exploits"
		author = "Florian Roth (Nextron Systems)"
		id = "59832d0a-0cb2-5eb9-a4e2-36aaa09a3998"
		date = "2017-01-08"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message7/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fvey_shadowbroker_jan17.yar#L10-L47"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8015b227c5df68fffadb86b72843b2b831d5603978ada3f50cc535a870aa94eb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "Danderspritz" ascii wide fullword
		$x2 = "DanderSpritz" ascii wide fullword
		$x3 = "PeddleCheap" ascii wide fullword
		$x4 = "ChimneyPool Addres" ascii wide fullword
		$a1 = "Getting remote time" fullword ascii
		$a2 = "RETRIEVED" fullword ascii
		$b1 = "Added Ops library to Python search path" fullword ascii
		$b2 = "target: z0.0.0.1" fullword ascii
		$c1 = "Psp_Avoidance" fullword ascii
		$c2 = "PasswordDump" fullword ascii
		$c4 = "EventLogEdit" fullword ascii
		$d1 = "Mcl_NtElevation" fullword ascii wide
		$d2 = "Mcl_NtNativeApi" fullword ascii wide
		$d3 = "Mcl_ThreatInject" fullword ascii wide
		$d4 = "Mcl_NtMemory" fullword ascii wide

	condition:
		filesize <2000KB and (1 of ($x*) or all of ($a*) or 1 of ($b*) or ( uint16(0)==0x5a4d and 1 of ($c*)) or 3 of ($c*) or ( uint16(0)==0x5a4d and 3 of ($d*)))
}
