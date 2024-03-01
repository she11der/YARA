rule SIGNATURE_BASE_CN_Honker_Sig_3389_2_3389 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file 3389.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8b2f5f6d-4d7b-561c-bd77-2de351e5aca8"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1983-L1999"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "48d1974215e5cb07d1faa57e37afa91482b5a376"
		logic_hash = "97e2a08dd391de44fc01c44ca6463aa009e93ad199a330eb99aaa809f14f2ef0"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "C:\\Documents and Settings\\Administrator\\" ascii
		$s2 = "net user guest /active:yes" fullword ascii
		$s3 = "\\Microsoft Word.exe" ascii

	condition:
		uint16(0)==0x5a4d and filesize <80KB and all of them
}
