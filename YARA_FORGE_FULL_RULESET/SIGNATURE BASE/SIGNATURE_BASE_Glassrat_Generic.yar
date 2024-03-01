rule SIGNATURE_BASE_Glassrat_Generic : FILE
{
	meta:
		description = "Detects GlassRAT Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "d09c4a9f-15ad-56d7-b015-94f494420e98"
		date = "2015-11-23"
		modified = "2023-12-05"
		reference = "https://blogs.rsa.com/peering-into-glassrat/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_glassRAT.yar#L45-L72"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "fdd309c403e53bfa80340c1334f90fd5ef5f4618737b19069a07f7aa63aeb23d"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "30d26aebcee21e4811ff3a44a7198a5c519843a24f334880384a7158e07ae399"
		hash2 = "3bdeb3805e9230361fb93c6ffb0bfec8d3aee9455d95b2428c7f6292d387d3a4"
		hash3 = "79993f1912958078c4d98503e00dc526eb1d0ca4d020d17b010efa6c515ca92e"
		hash4 = "a9b30b928ebf9cda5136ee37053fa045f3a53d0706dcb2343c91013193de761e"
		hash5 = "c11faf7290299bb13925e46d040ed59ab3ca8938eab1f171aa452603602155cb"
		hash6 = "d95fa58a81ab2d90a8cbe05165c00f9c8ad5b4f49e98df2ad391f5586893490d"
		hash7 = "f1209eb95ce1319af61f371c7f27bf6846eb90f8fd19e8d84110ebaf4744b6ea"

	strings:
		$s1 = "cmd.exe /c %s" fullword ascii
		$s2 = "update.dll" fullword ascii
		$s3 = "SYSTEM\\CurrentControlSet\\Services\\RasAuto\\Parameters" fullword ascii
		$s4 = "%%temp%%\\%u" fullword ascii
		$s5 = "\\off.dat" ascii
		$s6 = "rundll32 \"%s\",AddNum" fullword ascii
		$s7 = "cmd.exe /c erase /F \"%s\"" fullword ascii
		$s8 = "SYSTEM\\ControlSet00%d\\Services\\RasAuto" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <15MB and 5 of them
}
