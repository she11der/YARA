rule SIGNATURE_BASE_CN_Honker_Getlsasrvaddr : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file getlsasrvaddr.exe - WCE Amplia Security"
		author = "Florian Roth (Nextron Systems)"
		id = "fa0c0376-c5c3-5b48-b03e-86cefb547479"
		date = "2015-06-23"
		modified = "2022-12-21"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L809-L826"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a897d5da98dae8d80f3c0a0ef6a07c4b42fb89ce"
		logic_hash = "e626724430d0b74aee52783dd5abdb8ccc7b951c56041e5c166b78b7370bc402"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s8 = "pingme.txt" fullword ascii
		$s16 = ".\\lsasrv.pdb" ascii
		$s20 = "Addresses Found: " fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
