import "pe"

rule SIGNATURE_BASE_Antiy_Ports_1_21
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Antiy Ports 1.21.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "eb53fc91-4dec-5416-a2c7-1e8256297886"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2262-L2277"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ebf4bcc7b6b1c42df6048d198cbe7e11cb4ae3f0"
		logic_hash = "fb175c413faf0ca33cf166029b217aac31126d6cabc81883c16b2de2ab00c16c"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "AntiyPorts.EXE" fullword wide
		$s7 = "AntiyPorts MFC Application" fullword wide
		$s20 = " @Stego:" fullword ascii

	condition:
		all of them
}
