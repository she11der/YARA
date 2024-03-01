import "pe"
import "math"

rule SIGNATURE_BASE_Stonedrill : FILE
{
	meta:
		description = "Detects malware from StoneDrill threat report"
		author = "Florian Roth (Nextron Systems)"
		id = "92f53e6a-8f49-5ffa-8c16-3ec3e6f2bdcd"
		date = "2017-03-07"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_stonedrill.yar#L147-L170"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ef7173e259f985083d5451a2d464047b40112a084a05d471797d5dbf2d0fb21d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "2bab3716a1f19879ca2e6d98c518debb107e0ed8e1534241f7769193807aac83"
		hash2 = "62aabce7a5741a9270cddac49cd1d715305c1d0505e620bbeaec6ff9b6fd0260"
		hash3 = "69530d78c86031ce32583c6800f5ffc629acacb18aac4c8bb5b0e915fc4cc4db"

	strings:
		$x1 = "C-Dlt-C-Trsh-T.tmp" fullword wide
		$x2 = "C-Dlt-C-Org-T.vbs" fullword wide
		$s1 = "Hello dear" fullword ascii
		$s2 = "WRZRZRAR" fullword ascii
		$opa1 = { 66 89 45 d8 6a 64 ff }
		$opa2 = { 8d 73 01 90 0f bf 51 fe }

	condition:
		uint16(0)==0x5a4d and filesize <700KB and 1 of ($x*) or ( all of ($op*) and all of ($s*))
}
