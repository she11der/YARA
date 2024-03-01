rule SIGNATURE_BASE_Hscan_V1_20_Pipecmd : FILE
{
	meta:
		description = "Chinese Hacktool Set - file PipeCmd.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "957a8e3b-5f6c-5f3e-8973-88259c9cb0dc"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1028-L1049"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "64403ce63b28b544646a30da3be2f395788542d6"
		logic_hash = "91ed275896c2520893ba1af26b2563c0bd3564a9c5f9d812f35464469e27307b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "%SystemRoot%\\system32\\PipeCmdSrv.exe" fullword ascii
		$s2 = "PipeCmd.exe" fullword wide
		$s3 = "Please Use NTCmd.exe Run This Program." fullword ascii
		$s4 = "%s\\pipe\\%s%s%d" fullword ascii
		$s5 = "\\\\.\\pipe\\%s%s%d" fullword ascii
		$s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
		$s7 = "This is a service executable! Couldn't start directly." fullword ascii
		$s8 = "Connecting to Remote Server ...Failed" fullword ascii
		$s9 = "PIPECMDSRV" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 4 of them
}
