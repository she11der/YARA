rule SIGNATURE_BASE_Remoteexec_Tool : FILE
{
	meta:
		description = "Remote Access Tool used in APT Terracotta"
		author = "Florian Roth (Nextron Systems)"
		id = "c3262147-3455-554c-88fc-b523352efe7f"
		date = "2015-08-04"
		modified = "2023-12-05"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_terracotta.yar#L47-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a550131e106ff3c703666f15d55d9bc8c816d1cb9ac1b73c2e29f8aa01e53b78"
		logic_hash = "951cc65e14c2ff035ccc06d080730b1c25208caa1d30129074a6150557a5cebe"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "cmd.exe /q /c \"%s\"" fullword ascii
		$s1 = "\\\\.\\pipe\\%s%s%d" fullword ascii
		$s2 = "This is a service executable! Couldn't start directly." fullword ascii
		$s3 = "\\\\.\\pipe\\TermHlp_communicaton" fullword ascii
		$s4 = "TermHlp_stdout" fullword ascii
		$s5 = "TermHlp_stdin" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <75KB and 4 of ($s*)
}
