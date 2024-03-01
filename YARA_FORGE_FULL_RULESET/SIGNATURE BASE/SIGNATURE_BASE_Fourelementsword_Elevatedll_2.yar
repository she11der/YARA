rule SIGNATURE_BASE_Fourelementsword_Elevatedll_2 : FILE
{
	meta:
		description = "Detects FourElementSword Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "06879d75-18a3-5d49-a963-fa4bee379387"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_four_element_sword.yar#L89-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9c23febc49c7b17387767844356d38d5578727ee1150956164883cf555fe7f95"
		logic_hash = "d5fcb2bacfa0a1f78bfbd3fa7ba3084da9a60f1b8b7880c83d8f225312c179b4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Elevate.dll" fullword ascii
		$s2 = "GetSomeF" fullword ascii
		$s3 = "GetNativeSystemInfo" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <25KB and $s1) or ( all of them )
}
