import "pe"

rule DITEKSHEN_PUA_Win_Ultrasurf : FILE
{
	meta:
		description = "Detects UltraSurf / Ultrareach PUA"
		author = "ditekSHen"
		id = "ba0f6867-bddc-5e72-978c-8e29b1b6b709"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/malware.yar#L5792-L5807"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "d8d17b1bf20c12f864697d3dd66f345a8b93e2a75f0489b58b23b7f5264b6be3"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Ultrareach Internet Corp." ascii
		$s2 = "UltrasurfUnionRectUrlFixupWUse Proxy" ascii
		$s3 = "Ultrasurf UnlockFileUrlEscapeWUser-Agent" ascii wide
		$s4 = "Ultrasurf0#" ascii
		$m1 = "main.bindata_read" fullword ascii
		$m2 = "main.icon64_png" fullword ascii
		$m3 = "main.setProxy" fullword ascii
		$m4 = "main.openbrowser" fullword ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($s*) or ( all of ($m*) and 1 of ($s*)))
}
