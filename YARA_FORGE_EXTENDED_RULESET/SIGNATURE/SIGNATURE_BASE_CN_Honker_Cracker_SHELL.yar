rule SIGNATURE_BASE_CN_Honker_Cracker_SHELL : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SHELL.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "2249a058-7469-5054-9c51-cb20ef8197ca"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L932-L949"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c1dc349ff44a45712937a8a9518170da8d4ee656"
		logic_hash = "03da662e8d5dfbae524c4949d90e143714e6c4783e02600e059172e8b09ebc57"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "http://127.0.0.1/error1.asp" fullword ascii
		$s2 = "password,PASSWORD,pass,PASS,Lpass,lpass,Password" fullword wide
		$s3 = "\\SHELL" wide
		$s4 = "WebBrowser1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
