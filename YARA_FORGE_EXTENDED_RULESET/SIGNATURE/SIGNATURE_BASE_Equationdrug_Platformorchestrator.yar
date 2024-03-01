rule SIGNATURE_BASE_Equationdrug_Platformorchestrator
{
	meta:
		description = "EquationDrug - Platform orchestrator - mscfg32.dll, svchost32.dll"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		id = "ce19ed3c-9dd9-5cb0-99fe-c04fde057293"
		date = "2015-03-11"
		modified = "2023-12-05"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/spy_equation_fiveeyes.yar#L537-L554"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "febc4f30786db7804008dc9bc1cebdc26993e240"
		logic_hash = "26c3b84a00702f155daa50c8f17e5f37e1aac46adde8a06a711e732a4cd806e9"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "SERVICES.EXE" fullword wide
		$s1 = "\\command.com" wide
		$s2 = "Microsoft(R) Windows (TM) Operating System" fullword wide
		$s3 = "LSASS.EXE" fullword wide
		$s4 = "Windows Configuration Services" fullword wide
		$s8 = "unilay.dll" fullword ascii

	condition:
		all of them
}
