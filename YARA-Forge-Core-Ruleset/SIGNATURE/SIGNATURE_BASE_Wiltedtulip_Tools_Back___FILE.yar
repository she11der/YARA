rule SIGNATURE_BASE_Wiltedtulip_Tools_Back___FILE
{
	meta:
		description = "Detects Chrome password dumper used in Operation Wilted Tulip"
		author = "Florian Roth (Nextron Systems)"
		id = "3f57bd66-b269-5f59-ade1-f881b1d7dadd"
		date = "2017-07-23"
		modified = "2022-12-21"
		reference = "http://www.clearskysec.com/tulip"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_wilted_tulip.yar#L13-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "3a23491cbb24177c027695d8f677c4a72ed0404c4c38356eec4b92f2d06be2ee"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b7faeaa6163e05ad33b310a8fdc696ccf1660c425fa2a962c3909eada5f2c265"

	strings:
		$x1 = "%s.exe -f \"C:\\Users\\Admin\\Google\\Chrome\\TestProfile\" -o \"c:\\passlist.txt\"" fullword ascii
		$x2 = "\\ChromePasswordDump\\Release\\FireMaster.pdb" ascii
		$x3 = "//Dump Chrome Passwords to a Output file \"c:\\passlist.txt\"" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 1 of them )
}