rule SIGNATURE_BASE_Waterbear_2_Jun17 : FILE
{
	meta:
		description = "Detects malware from Operation Waterbear"
		author = "Florian Roth (Nextron Systems)"
		id = "d3178f01-90a8-5a82-9c95-40bf8e9b567f"
		date = "2017-06-23"
		modified = "2023-12-05"
		reference = "https://goo.gl/L9g9eR"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_waterbear.yar#L27-L43"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ec0b8d7313f925adafb7f03c8b7fd12c0176b75c74c642eeee900e911e0662a7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "dcb5c350af76c590002a8ea00b01d862b4d89cccbec3908bfe92fdf25eaa6ea4"

	strings:
		$s1 = "downloading movie" fullword ascii
		$s2 = "name=\"test.exe\"/>" fullword ascii
		$s3 = "<description>Test Application</description>" fullword ascii
		$s4 = "UI look 2003" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them )
}
