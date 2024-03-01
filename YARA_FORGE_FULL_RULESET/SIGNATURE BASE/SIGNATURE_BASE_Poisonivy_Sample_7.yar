rule SIGNATURE_BASE_Poisonivy_Sample_7 : FILE
{
	meta:
		description = "Detects PoisonIvy RAT sample set"
		author = "Florian Roth (Nextron Systems)"
		id = "01224053-d95e-5144-981b-76cd7e57e1c3"
		date = "2015-06-03"
		modified = "2023-12-05"
		reference = "VT Analysis"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_poisonivy.yar#L166-L185"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9480cf544beeeb63ffd07442233eb5c5f0cf03b3"
		logic_hash = "28db3fb7fa5b5e60ad1d1cc2b6d3d9d30a1948491105439201574ca354eb8bd1"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Microsoft Software installation Service" fullword wide
		$s2 = "pidll.dll" fullword ascii
		$s10 = "ServiceMain" fullword ascii
		$s11 = "ZwSetInformationProcess" fullword ascii
		$s12 = "Software installation Service" fullword wide
		$s13 = "Microsoft(R) Windows(R) Operating System" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
