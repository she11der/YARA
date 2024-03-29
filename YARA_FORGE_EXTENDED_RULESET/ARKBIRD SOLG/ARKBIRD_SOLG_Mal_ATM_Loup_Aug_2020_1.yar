import "pe"

rule ARKBIRD_SOLG_Mal_ATM_Loup_Aug_2020_1 : FILE
{
	meta:
		description = "Detect ATM malware Loup by theirs strings."
		author = "Arkbird_SOLG"
		id = "07c0fe02-a82a-58a7-8776-748a1c986f93"
		date = "2020-08-17"
		modified = "2020-08-18"
		reference = "https://twitter.com/r3c0nst/status/1295275546780327936"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-08-17/Loup/Mal_ATM_Loup_Aug_2020_1.yar#L3-L34"
		license_url = "N/A"
		logic_hash = "18e4d6af5d89746b42c87d7311e442f61deff3bfcbf57cc008d87290e91baafb"
		score = 75
		quality = 67
		tags = "FILE"
		hash1 = "6c9e9f78963ab3e7acb43826906af22571250dc025f9e7116e0201b805dc1196"

	strings:
		$pdb1 = "C:\\Users\\muham\\source\\repos\\loup\\Debug\\loup.pdb" fullword ascii
		$pdb2 = "PDBOpenValidate5" fullword ascii
		$dbg1 = "Run-Time Check Failure #%d - %s" fullword ascii
		$dbg2 = "Unknown Filename" fullword ascii
		$dbg3 = "Unknown Module Name" fullword ascii
		$info1 = "%s%s%p%s%zd%s%d%s%s%s%s%s" fullword ascii
		$info2 = { 41 64 64 72 65 73 73 3a 20 30 78 }
		$info3 = { 53 69 7a 65 3a }
		$info4 = { 44 61 74 61 3a }
		$s1 = "MSXFS.dll" fullword ascii
		$s2 = "WFSExecute" fullword ascii
		$s3 = "WfsVersion" fullword ascii
		$s4 = "SvcVersion" fullword ascii
		$s5 = "SpiVersion" fullword ascii
		$s6 = "CurrencyDispenser1" fullword ascii
		$s7 = "WFSUnlock" fullword ascii
		$s8 = "WFSFreeResult" fullword ascii
		$s9 = "WFSCleanUp" fullword ascii
		$s10 = "WFSOpen" fullword ascii
		$s11 = "WFSClose" fullword ascii
		$s12 = "WFSStartUp" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and (pe.imphash()=="190fc01f66c40478aa91be89a98c57e9" and (1 of ($pdb*) and 2 of ($dbg*) and 2 of ($info*) and 9 of ($s*)))
}
