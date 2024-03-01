rule SIGNATURE_BASE_Regin_APT_Kerneldriver_Generic_A : FILE
{
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		id = "4cea1d45-b797-51b2-baa7-e66c8c0206ea"
		date = "2014-11-23"
		modified = "2023-12-15"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/spy_regin_fiveeyes.yar#L14-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "1cc367dff184f2b458a2b7c0c88a44095714525ca6bb115d03e6331cf1f22116"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "187044596bc1328efa0ed636d8aa4a5c"
		hash2 = "06665b96e293b23acc80451abb413e50"
		hash3 = "d240f06e98c8d3e647cbf4d442d79475"

	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 }
		$m1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
		$s0 = "atapi.sys" fullword wide
		$s1 = "disk.sys" fullword wide
		$s3 = "h.data" fullword ascii
		$s4 = "\\system32" ascii
		$s5 = "\\SystemRoot" ascii
		$s6 = "system" fullword ascii
		$s7 = "temp" fullword ascii
		$s8 = "windows" fullword ascii
		$x1 = "LRich6" fullword ascii
		$x2 = "KeServiceDescriptorTable" fullword ascii

	condition:
		uint16(0)==0x5a4d and $m0 at 0 and $m1 and all of ($s*) and 1 of ($x*)
}
