rule SIGNATURE_BASE_Telebots_VBS_Backdoor_2 : FILE
{
	meta:
		description = "Detects TeleBots malware - VBS Backdoor"
		author = "Florian Roth (Nextron Systems)"
		id = "151849af-f1d0-529c-94f2-287312f6515e"
		date = "2016-12-14"
		modified = "2023-12-05"
		reference = "https://goo.gl/4if3HG"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_telebots.yar#L108-L123"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "299a2ca6eacc29b4a7697a8502a56cffda4f6bc6b3354d3cc133712c1755c476"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1b2a5922b58c8060844b43e14dfa5b0c8b119f281f54a46f0f1c34accde71ddb"

	strings:
		$s1 = "cmd = \"cmd.exe /c \" + arg + \" \" + arg2" fullword ascii
		$s2 = "Dim WMI:  Set WMI = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")" fullword ascii
		$s3 = "cmd = \"certutil -encode -f \" + source + \" \" + dest" fullword ascii

	condition:
		( uint16(0)==0x6944 and filesize <30KB and 1 of them ) or (2 of them )
}
