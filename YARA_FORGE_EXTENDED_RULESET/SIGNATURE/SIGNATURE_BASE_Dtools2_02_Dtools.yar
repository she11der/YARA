rule SIGNATURE_BASE_Dtools2_02_Dtools : FILE
{
	meta:
		description = "Chinese Hacktool Set - file DTools.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "fc812797-12d8-596a-8ebe-dd8b0d7a4b7e"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L161-L179"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "9f99771427120d09ec7afa3b21a1cb9ed720af12"
		logic_hash = "51e30d39f388546ac233b4b97a38f225c90d2f006bc509dd7eecfb408aef9be5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "kernel32.dll" ascii
		$s1 = "TSETPASSWORDFORM" fullword wide
		$s2 = "TGETNTUSERNAMEFORM" fullword wide
		$s3 = "TPORTFORM" fullword wide
		$s4 = "ShellFold" fullword ascii
		$s5 = "DefaultPHotLigh" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
