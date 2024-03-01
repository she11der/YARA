rule SIGNATURE_BASE_Sofacy_Jun16_Sample2 : FILE
{
	meta:
		description = "Detects Sofacy Malware mentioned in PaloAltoNetworks APT report"
		author = "Florian Roth (Nextron Systems)"
		id = "21561e13-a190-565e-a08b-e6a07c84c3db"
		date = "2016-06-14"
		modified = "2023-12-05"
		reference = "http://goo.gl/mzAa97"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sofacy_jun16.yar#L27-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a1f334996527556334c34d0308da6165e9d2a3d7eb8b2ecc322b574dea4d4844"
		score = 85
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "57d230ddaf92e2d0504e5bb12abf52062114fb8980c5ecc413116b1d6ffedf1b"
		hash2 = "69940a20ab9abb31a03fcefe6de92a16ed474bbdff3288498851afc12a834261"
		hash3 = "aeeab3272a2ed2157ebf67f74c00fafc787a2b9bbaa17a03be1e23d4cb273632"

	strings:
		$x1 = "DGMNOEP" fullword ascii
		$x2 = "/%s%s%s/?%s=" fullword ascii
		$s1 = "Control Panel\\Dehttps=https://%snetwork.proxy.ht2" fullword ascii
		$s2 = "http=http://%s:%Control Panel\\Denetwork.proxy.ht&ol1mS9" fullword ascii
		$s3 = "svchost.dll" fullword wide
		$s4 = "clconfig.dll" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and ( all of ($x*))) or (3 of them )
}
