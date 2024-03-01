rule SIGNATURE_BASE_Telebots_VBS_Backdoor_1 : FILE
{
	meta:
		description = "Detects TeleBots malware - VBS Backdoor"
		author = "Florian Roth (Nextron Systems)"
		id = "2b711f66-8ec5-5b9a-a762-7e6668c821c9"
		date = "2016-12-14"
		modified = "2023-12-05"
		reference = "https://goo.gl/4if3HG"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_telebots.yar#L90-L106"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4ff4963058674cf71c123af74c0947da2edf3b5e2622261d14200f406dbe2992"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "eb31a918ccc1643d069cf08b7958e2760e8551ba3b88ea9e5d496e07437273b2"

	strings:
		$s1 = "cmd = \"cmd.exe /c \" + arg + \" >\" + outfile +\" 2>&1\"" fullword ascii
		$s2 = "GetTemp = \"c:\\WINDOWS\\addins\"" fullword ascii
		$s3 = "elseif (arg0 = \"-dump\") Then" fullword ascii
		$s4 = "decode = \"certutil -decode \" + source + \" \" + dest  " fullword ascii

	condition:
		( uint16(0)==0x6553 and filesize <8KB and 1 of them ) or ( all of them )
}
