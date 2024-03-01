rule SIGNATURE_BASE_CN_Honker_Webshell_ASP_Rootkit : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file rootkit.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "ab51abca-0790-541c-9f18-1568809ef113"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L1066-L1081"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3bfc1c95782e702cf56184e7d438edcf5802eab3"
		logic_hash = "5569a179f011ece9802676542d5556fe8d2a2b144e26065b9e0c5bd06c970201"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "set ss=zsckm.get(\"Win32_ProcessSta\"&uyy&\"rtup\")" fullword ascii
		$s1 = "If jzgm=\"\"Then jzgm=\"cmd.exe /c net user\"" fullword ascii

	condition:
		filesize <80KB and all of them
}
