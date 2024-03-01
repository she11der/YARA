rule SIGNATURE_BASE_Tools_Xport : FILE
{
	meta:
		description = "Chinese Hacktool Set - file xport.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3223fe5b-6135-5530-a5eb-10c44f3f6277"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1544-L1565"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "9584de562e7f8185f721e94ee3cceac60db26dda"
		logic_hash = "9eea73732643f74b4802af0672f5c3ab09cc54cfecd80f8903efc26b7ceaec29"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Match operate system failed, 0x%00004X:%u:%d(Window:TTL:DF)" fullword ascii
		$s2 = "Example: xport www.xxx.com 80 -m syn" fullword ascii
		$s3 = "%s - command line port scanner" fullword ascii
		$s4 = "xport 192.168.1.1 1-1024 -t 200 -v" fullword ascii
		$s5 = "Usage: xport <Host> <Ports Scope> [Options]" fullword ascii
		$s6 = ".\\port.ini" fullword ascii
		$s7 = "Port scan complete, total %d port, %d port is opened, use %d ms." fullword ascii
		$s8 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s9 = "http://www.xfocus.org" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 2 of them
}
