rule SIGNATURE_BASE_Stuxnet_Dll : FILE
{
	meta:
		description = "Stuxnet Sample - file dll.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "92d812a6-2622-56e4-96c5-eb65ab7055b9"
		date = "2016-07-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_stuxnet.yar#L59-L72"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0c192153c268fdd330d3b9e2eb0d8383bd50ce6d036409f0cc0c9273ba8201b3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9e392277f62206098cf794ddebafd2817483cfd57ec03c2e05e7c3c81e72f562"

	strings:
		$s1 = "SUCKM3 FROM EXPLORER.EXE MOTH4FUCKA #@!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and $s1
}
