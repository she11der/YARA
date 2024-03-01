import "pe"

rule ARKBIRD_SOLG_Ran_Mem_Ragnarlocker_Nov_2020_1 : FILE
{
	meta:
		description = "Detect memory artefacts of the Ragnarlocker ransomware (Nov 2020)"
		author = "Arkbird_SOLG"
		id = "910774ab-9ad6-5c56-a921-203f61c9d7f7"
		date = "2020-11-26"
		modified = "2020-11-27"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-11-27/Ran_RagnarLocker_Nov_2020_1.yar#L3-L33"
		license_url = "N/A"
		logic_hash = "2cb26677b8f4e464750eb8dec0638fd3f9a28500e68f64d62e99236c93895c85"
		score = 75
		quality = 50
		tags = "FILE"
		hash1 = "041fd213326dd5c10a16caf88ff076bb98c68c052284430fba5f601023d39a14"
		hash2 = "dd79b2abc21e766fe3076038482ded43e5069a1af9e0ad29e06dce387bfae900"

	strings:
		$s1 = "\\\\.\\PHYSICALDRIVE%d" fullword wide
		$s2 = "bootfont.bin" fullword wide
		$s3 = "bootsect.bak" fullword wide
		$s4 = "bootmgr.efi" fullword wide
		$s5 = "---RAGNAR SECRET---" fullword ascii
		$s6 = "Mozilla"
		$s7 = "Internet Explorer" fullword wide
		$s8 = "  </trustInfo>" fullword ascii
		$s9 = "Tor browser" fullword wide
		$s10 = "Opera Software" fullword wide
		$s11 = "---END RAGN KEY---" fullword ascii
		$s12 = "---BEGIN RAGN KEY---" fullword ascii
		$s13 = "%s-%s-%s-%s-%s" fullword wide
		$s14 = "$Recycle.Bin" fullword wide
		$s15 = "***********************************************************************************" fullword ascii
		$s16 = "K<^_[]" fullword ascii
		$s17 = "SD;SDw" fullword ascii
		$s18 = "Windows.old" fullword wide
		$s19 = "iconcache.db" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize >30KB and 12 of them
}
