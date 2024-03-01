rule SIGNATURE_BASE_Whosthere : FILE
{
	meta:
		description = "Auto-generated rule - file whosthere.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "92e98381-9142-58af-82ce-4df9eb0a0039"
		date = "2015-07-10"
		modified = "2023-12-05"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_passthehashtoolkit.yar#L136-L155"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d7a82204d3e511cf5af58eabdd6e9757c5dd243f9aca3999dc0e5d1603b1fa37"
		logic_hash = "a13c8a1fc66381b040d6449fe9655191d7a1762da0dc70789cd497fb68fb2a55"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii
		$s2 = "whosthere enters an infinite loop and searches for new logon sessions every 2 seconds. Only new sessions are shown if found." fullword ascii
		$s3 = "specify addresses to use. Format: ADDCREDENTIAL_ADDR:ENCRYPTMEMORY_ADDR:FEEDBACK_ADDR:DESKEY_ADDR:LOGONSESSIONLIST_ADDR:LOGONSES" ascii
		$s4 = "Could not enable debug privileges. You must run this tool with an account with administrator privileges." fullword ascii
		$s5 = "-B is now used by default. Trying to find correct addresses.." fullword ascii
		$s6 = "Cannot get LSASS.EXE PID!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <320KB and 2 of them
}
