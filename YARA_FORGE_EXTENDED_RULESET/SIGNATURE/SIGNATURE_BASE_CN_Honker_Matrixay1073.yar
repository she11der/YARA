rule SIGNATURE_BASE_CN_Honker_Matrixay1073 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file MatriXay1073.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "23e73b89-f60e-5bc3-8974-15be16d7c408"
		date = "2015-06-23"
		modified = "2023-01-27"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L394-L412"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "fef951e47524f827c7698f4508ba9551359578a5"
		logic_hash = "e64cae48344e5dae8ec80b2897305a0b380340bdd2973eb0828582f18ef8bf2b"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1" ascii
		$s1 = "Policy\\Scan\\GetUserLen.ini" fullword ascii
		$s2 = "!YEL!Using http://127.0.0.1:%d/ to visiter https://%s:%d/" ascii
		$s3 = "getalluserpasswordhash" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <9100KB and all of them
}
