import "pe"

rule SIGNATURE_BASE_Disclosed_0Day_Pocs_Injector : FILE
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		author = "Florian Roth (Nextron Systems)"
		id = "6de89a84-fe16-5064-8cbb-a3b9003f4c0c"
		date = "2017-07-07"
		modified = "2023-12-05"
		reference = "Disclosed 0day Repos"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3765-L3785"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "37ed19fe19d3645adcd5fa7d6f6b3572d2821fdb78a6d0c8afdba6ccecfc8528"
		score = 75
		quality = 60
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ba0e2119b2a6bad612e86662b643a404426a07444d476472a71452b7e9f94041"

	strings:
		$x1 = "\\Release\\injector.pdb" ascii
		$x2 = "Cannot write the shellcode in the process memory, error: " fullword ascii
		$x3 = "/s shellcode_file PID: shellcode injection." fullword ascii
		$x4 = "/d dll_file PID: dll injection via LoadLibrary()." fullword ascii
		$x5 = "/s shellcode_file PID" fullword ascii
		$x6 = "Shellcode copied in memory: OK" fullword ascii
		$x7 = "Usage of the injector. " fullword ascii
		$x8 = "KO: cannot obtain the SeDebug privilege." fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <90KB and 1 of them ) or 3 of them
}
