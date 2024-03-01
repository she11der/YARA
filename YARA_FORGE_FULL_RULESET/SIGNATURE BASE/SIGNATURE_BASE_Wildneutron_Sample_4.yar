rule SIGNATURE_BASE_Wildneutron_Sample_4 : FILE
{
	meta:
		description = "Wild Neutron APT Sample Rule"
		author = "Florian Roth (Nextron Systems)"
		id = "52ff5770-1ca4-54d9-b69d-8af0c392084e"
		date = "2015-07-10"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_wildneutron.yar#L85-L108"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b4005530193bc523d3e0193c3c53e2737ae3bf9f76d12c827c0b5cd0dcbaae45"
		logic_hash = "4882b7c5f469615436490cd628ee3bb5b0dded43fb556ac6477cdadc6c8eff05"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "WinRAT-Win32-Release.exe" fullword ascii
		$s0 = "rundll32.exe \"%s\",#1" fullword wide
		$s1 = "RtlUpd.EXE" fullword wide
		$s2 = "RtlUpd.exe" fullword wide
		$s3 = "Driver Update and remove for Windows x64 or x86_32" fullword wide
		$s4 = "Realtek HD Audio Update and remove driver Tool" fullword wide
		$s5 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide
		$s6 = "Key Usage" fullword ascii
		$s7 = "id-at-serialNumber" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1240KB and all of them
}
