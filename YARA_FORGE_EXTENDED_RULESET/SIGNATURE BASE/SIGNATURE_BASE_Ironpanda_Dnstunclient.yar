rule SIGNATURE_BASE_Ironpanda_Dnstunclient : FILE
{
	meta:
		description = "Iron Panda malware DnsTunClient - file named.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "dd608176-d7e7-5819-a7d4-e8b89d4a59c2"
		date = "2015-09-16"
		modified = "2023-12-05"
		reference = "https://goo.gl/E4qia9"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_irontiger.yar#L10-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a08db49e198068709b7e52f16d00a10d72b4d26562c0d82b4544f8b0fb259431"
		logic_hash = "07c142f6eb11ecc8ed5f55d6b0cc7110c6268e189f3ce29215f75b7aba91a290"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "dnstunclient -d or -domain <domain>" fullword ascii
		$s2 = "dnstunclient -ip <server ip address>" fullword ascii
		$s3 = "C:\\Windows\\System32\\cmd.exe /C schtasks /create /tn \"\\Microsoft\\Windows\\PLA\\System\\Microsoft Windows\" /tr " fullword ascii
		$s4 = "C:\\Windows\\System32\\cmd.exe /C schtasks /create /tn \"Microsoft Windows\" /tr " fullword ascii
		$s5 = "taskkill /im conime.exe" fullword ascii
		$s6 = "\\dns control\\t-DNSTunnel\\DnsTunClient\\DnsTunClient.cpp" ascii
		$s7 = "UDP error:can not bing the port(if there is unclosed the bind process?)" fullword ascii
		$s8 = "use error domain,set domain pls use -d or -domain mark(Current: %s,recv %s)" fullword ascii
		$s9 = "error: packet num error.the connection have condurt,pls try later" fullword ascii
		$s10 = "Coversation produce one error:%s,coversation fail" fullword ascii
		$s11 = "try to add many same pipe to select group(or mark is too easy)." fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 2 of them ) or 5 of them
}
