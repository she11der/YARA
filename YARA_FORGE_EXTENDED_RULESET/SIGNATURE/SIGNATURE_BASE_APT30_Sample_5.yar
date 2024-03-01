rule SIGNATURE_BASE_APT30_Sample_5 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "bdbebe44-7423-5793-8a42-4f9b70de2231"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L110-L127"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "1a2dd2a0555dc746333e7c956c58f7c4cdbabd4b"
		logic_hash = "3738076d97bf19404bad20c2419eae83dd2b65400d5bd135ffe73362c008de9b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Version 4.7.3001" fullword wide
		$s1 = "Copyright (c) Microsoft Corporation 2004" fullword wide
		$s3 = "Microsoft(R) is a registered trademark of Microsoft Corporation in the U" wide
		$s7 = "msmsgs" fullword wide
		$s10 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
