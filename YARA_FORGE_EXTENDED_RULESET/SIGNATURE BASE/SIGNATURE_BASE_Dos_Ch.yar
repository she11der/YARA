rule SIGNATURE_BASE_Dos_Ch : FILE
{
	meta:
		description = "Chinese Hacktool Set - file ch.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "2e8319de-fe54-5083-968c-4707d127f072"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L239-L257"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "60bbb87b08af840f21536b313a76646e7c1f0ea7"
		logic_hash = "49ab2c75267c2ed5c15c8fbdc6fa0f8826f6e7a45a2861d6ba4b293ffca6bcd6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "/Churraskito/-->Usage: Churraskito.exe \"command\" " fullword ascii
		$s4 = "fuck,can't find WMI process PID." fullword ascii
		$s5 = "/Churraskito/-->Found token %s " fullword ascii
		$s8 = "wmiprvse.exe" fullword ascii
		$s10 = "SELECT * FROM IIsWebInfo" fullword ascii
		$s17 = "WinSta0\\Default" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <260KB and 3 of them
}
