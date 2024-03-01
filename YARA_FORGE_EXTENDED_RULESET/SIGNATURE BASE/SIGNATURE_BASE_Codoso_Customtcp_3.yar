rule SIGNATURE_BASE_Codoso_Customtcp_3 : FILE
{
	meta:
		description = "Detects Codoso APT CustomTCP Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "b6ed6939-db0c-5a47-8839-3337d1bc1f6c"
		date = "2016-01-30"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_codoso.yar#L72-L93"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d66106ec2e743dae1d71b60a602ca713b93077f56a47045f4fc9143aa3957090"
		logic_hash = "fb486985587fc28c45cbdf6a63550e60e8d6c18f218544adc19c5604193fe8ea"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "DnsApi.dll" fullword ascii
		$s2 = "softWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\%s" ascii
		$s3 = "CONNECT %s:%d hTTP/1.1" ascii
		$s4 = "CONNECT %s:%d HTTp/1.1" ascii
		$s5 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0;)" ascii
		$s6 = "iphlpapi.dll" ascii
		$s7 = "%systemroot%\\Web\\" ascii
		$s8 = "Proxy-Authorization: Negotiate %s" ascii
		$s9 = "CLSID\\{%s}\\InprocServer32" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and 5 of them ) or 7 of them
}
