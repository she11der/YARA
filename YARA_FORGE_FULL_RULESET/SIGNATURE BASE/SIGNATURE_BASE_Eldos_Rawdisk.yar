rule SIGNATURE_BASE_Eldos_Rawdisk : FILE
{
	meta:
		description = "EldoS Rawdisk Device Driver (Commercial raw disk access driver - used in Operation Shamoon 2.0)"
		author = "Florian Roth (Nextron Systems) (with Binar.ly)"
		id = "8a43f425-86b7-5a05-b7c3-13c78aa905f8"
		date = "2016-12-01"
		modified = "2023-01-27"
		reference = "https://goo.gl/jKIfGB"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_shamoon2.yar#L50-L75"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ab09371b91ab6889f342c7992108ad374b5ecf67b6c2144a6282670f177d0f15"
		score = 50
		quality = 85
		tags = "FILE"
		hash1 = "47bb36cd2832a18b5ae951cf5a7d44fba6d8f5dca0a372392d40f51d1fe1ac34"
		hash2 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"

	strings:
		$s1 = "g\\system32\\" wide
		$s2 = "ztvttw" fullword wide
		$s3 = "lwizvm" fullword ascii
		$s4 = "FEJIKC" fullword ascii
		$s5 = "INZQND" fullword ascii
		$s6 = "IUTLOM" fullword wide
		$s7 = "DKFKCK" fullword ascii
		$op1 = { 94 35 77 73 03 40 eb e9 }
		$op2 = { 80 7c 41 01 00 74 0a 3d }
		$op3 = { 74 0a 3d 00 94 35 77 }

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 4 of them )
}
