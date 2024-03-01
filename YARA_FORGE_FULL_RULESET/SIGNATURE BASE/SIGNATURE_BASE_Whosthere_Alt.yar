rule SIGNATURE_BASE_Whosthere_Alt : FILE
{
	meta:
		description = "Auto-generated rule - file whosthere-alt.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "92e98381-9142-58af-82ce-4df9eb0a0039"
		date = "2015-07-10"
		modified = "2023-12-05"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_passthehashtoolkit.yar#L10-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9b4c3691872ca5adf6d312b04190c6e14dd9cbe10e94c0dd3ee874f82db897de"
		logic_hash = "ef7bccb8f63034b885cfaec27663c9b038cd9b1811b4f25a9eae28640dac248b"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "WHOSTHERE-ALT v1.1 - by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii
		$s1 = "whosthere enters an infinite loop and searches for new logon sessions every 2 seconds. Only new sessions are shown if found." fullword ascii
		$s2 = "dump output to a file, -o filename" fullword ascii
		$s3 = "This tool lists the active LSA logon sessions with NTLM credentials." fullword ascii
		$s4 = "Error: pth.dll is not in the current directory!." fullword ascii
		$s5 = "the output format is: username:domain:lmhash:nthash" fullword ascii
		$s6 = ".\\pth.dll" fullword ascii
		$s7 = "Cannot get LSASS.EXE PID!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <280KB and 2 of them
}
