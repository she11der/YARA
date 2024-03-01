import "pe"
import "math"

rule SIGNATURE_BASE_Stonedrill_Ntssrvr32 : FILE
{
	meta:
		description = "Detects malware from StoneDrill threat report"
		author = "Florian Roth (Nextron Systems)"
		id = "92f53e6a-8f49-5ffa-8c16-3ec3e6f2bdcd"
		date = "2017-03-07"
		modified = "2023-01-27"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_stonedrill.yar#L98-L118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f1122aba53f32b10bd5f43cb619aa5d668b1457f3a5ea2a68c97254ab8631faa"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"

	strings:
		$s1 = "g\\system32\\" wide
		$s2 = "ztvttw" fullword wide
		$s3 = "lwizvm" fullword ascii
		$op1 = { 94 35 77 73 03 40 eb e9 }
		$op2 = { 80 7c 41 01 00 74 0a 3d }
		$op3 = { 74 0a 3d 00 94 35 77 }

	condition:
		( uint16(0)==0x5a4d and filesize <4000KB and 3 of them )
}
