import "pe"

rule SIGNATURE_BASE_Snifferport
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file snifferport.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "5b903344-18d2-5d3d-be66-7260a5f3ea4b"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1714-L1731"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d14133b5eaced9b7039048d0767c544419473144"
		logic_hash = "361f1a55ed4bd5a7a5d01d346c4efd1b83e701363484282235b5aab18d3abe1a"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "iphlpapi.DLL" fullword ascii
		$s5 = "ystem\\CurrentCorolSet\\" ascii
		$s11 = "Port.TX" fullword ascii
		$s12 = "32Next" fullword ascii
		$s13 = "V1.2 B" fullword ascii

	condition:
		all of them
}
