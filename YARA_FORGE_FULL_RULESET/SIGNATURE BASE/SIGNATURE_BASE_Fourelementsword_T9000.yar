rule SIGNATURE_BASE_Fourelementsword_T9000 : FILE
{
	meta:
		description = "Detects FourElementSword Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "35ae844e-52e1-5e6f-984d-aa75ebd2f60f"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_four_element_sword.yar#L30-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
		logic_hash = "1c7b063cbe9d44a9d194a180570f8313460f61560ac2cda5d66e048934170faa"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "D:\\WORK\\T9000\\" ascii
		$x2 = "%s\\temp\\HHHH.dat" fullword wide
		$s1 = "Elevate.dll" fullword wide
		$s2 = "ResN32.dll" fullword wide
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword wide
		$s4 = "igfxtray.exe" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and 1 of ($x*)) or ( all of them )
}
