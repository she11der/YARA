rule SIGNATURE_BASE_Codoso_PGV_PVID_4 : FILE
{
	meta:
		description = "Detects Codoso APT PlugX Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "c1c753a6-77b6-5bfb-89f9-16127c264fd0"
		date = "2016-01-30"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_codoso.yar#L248-L275"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "f24100c0fe837511ce6144224eda397fed3931072e364f1b5be49c7bb4102aa4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
		hash2 = "8a56b476d792983aea0199ee3226f0d04792b70a1c1f05f399cb6e4ce8a38761"
		hash3 = "b2950f2e09f5356e985c38b284ea52175d21feee12e582d674c0da2233b1feb1"
		hash4 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
		hash5 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"

	strings:
		$x1 = "dropper, Version 1.0" fullword wide
		$x2 = "dropper" fullword wide
		$x3 = "DROPPER" fullword wide
		$x4 = "About dropper" fullword wide
		$s1 = "Microsoft Windows Manager Utility" fullword wide
		$s2 = "SYSTEM\\CurrentControlSet\\Services\\" ascii
		$s3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" fullword ascii
		$s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
		$s5 = "<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"></supportedOS>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <900KB and 2 of ($x*) and 2 of ($s*)
}
