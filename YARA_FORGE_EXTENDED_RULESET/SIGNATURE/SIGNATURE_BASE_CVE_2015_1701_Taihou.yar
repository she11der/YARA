rule SIGNATURE_BASE_CVE_2015_1701_Taihou : CVE_2015_1701 FILE
{
	meta:
		description = "CVE-2015-1701 compiled exploit code"
		author = "Florian Roth (Nextron Systems)"
		id = "58250e17-aa46-5451-ae6d-18fb4030f8df"
		date = "2015-05-13"
		modified = "2023-12-05"
		reference = "http://goo.gl/W4nU0q"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/exploit_cve_2015_1701.yar#L2-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d230e036c303642c40bdf83be2b097f6e447a7e7d4292c495179edbae8a4124c"
		score = 70
		quality = 85
		tags = "CVE-2015-1701, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "90d17ebd75ce7ff4f15b2df951572653efe2ea17"
		hash2 = "acf181d6c2c43356e92d4ee7592700fa01e30ffb"
		hash3 = "b8aabe12502f7d55ae332905acee80a10e3bc399"
		hash4 = "d9989a46d590ebc792f14aa6fec30560dfe931b1"
		hash5 = "63d1d33e7418daf200dc4660fc9a59492ddd50d9"

	strings:
		$s3 = "VirtualProtect" fullword
		$s4 = "RegisterClass"
		$s5 = "LoadIcon"
		$s6 = "PsLookupProcessByProcessId" fullword ascii
		$s7 = "LoadLibraryExA" fullword ascii
		$s8 = "gSharedInfo" fullword
		$w1 = "user32.dll" wide
		$w2 = "ntdll" wide

	condition:
		uint16(0)==0x5a4d and filesize <160KB and all of ($s*) and 1 of ($w*)
}
