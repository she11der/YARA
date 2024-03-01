rule SIGNATURE_BASE_Backdoor_Nitol_Jun17 : FILE
{
	meta:
		description = "Detects malware backdoor Nitol - file wyawou.exe - Attention: this rule also matches on Upatre Downloader"
		author = "Florian Roth (Nextron Systems)"
		id = "7dd26868-59e0-51a1-b12a-3b69d6246ff5"
		date = "2017-06-04"
		modified = "2023-01-07"
		reference = "https://goo.gl/OOB3mH"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eternalblue_non_wannacry.yar#L38-L61"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "9035b8bd74c284f170f8c9767d96580dba243786abaa3b2e79e05a981f8fa204"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "cba19d228abf31ec8afab7330df3c9da60cd4dae376552b503aea6d7feff9946"

	strings:
		$x1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" fullword ascii
		$x2 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
		$x3 = "TCPConnectFloodThread.target = %s" fullword ascii
		$s1 = "\\Program Files\\Internet Explorer\\iexplore.exe" ascii
		$s2 = "%c%c%c%c%c%c.exe" fullword ascii
		$s3 = "GET %s%s HTTP/1.1" fullword ascii
		$s4 = "CCAttack.target = %s" fullword ascii
		$s5 = "Accept-Language: zh-cn" fullword ascii
		$s6 = "jdfwkey" fullword ascii
		$s7 = "hackqz.f3322.org:8880" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and (1 of ($x*) or 5 of ($s*))) or ( all of them )
}
