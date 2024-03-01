rule SIGNATURE_BASE_APT30_Sample_12 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L314-L329"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b02b5720ff0f73f01eb2ba029a58b645c987c4bc"
		logic_hash = "997c91267f956bd7d2a7edca9817ebc80bbf1eed944b3bc01cc8bb01927deb1e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Richic" fullword ascii
		$s1 = "Accept: image/gif, */*" fullword ascii
		$s2 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii

	condition:
		filesize <250KB and uint16(0)==0x5A4D and all of them
}
