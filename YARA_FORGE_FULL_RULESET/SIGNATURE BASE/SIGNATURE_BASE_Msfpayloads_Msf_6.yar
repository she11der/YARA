rule SIGNATURE_BASE_Msfpayloads_Msf_6
{
	meta:
		description = "Metasploit Payloads - file msf.vbs"
		author = "Florian Roth (Nextron Systems)"
		id = "5485102b-e709-5111-814a-e6878b4bd889"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_metasploit_payloads.yar#L158-L177"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b9498828a55477049922e50329d0c38ee34b8484562113a2686669ccbb8b3318"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8d6f55c6715c4a2023087c3d0d7abfa21e31a629393e4dc179d31bb25b166b3f"

	strings:
		$s1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
		$s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
		$s3 = ".GetSpecialFolder(2)" ascii
		$s4 = ".Write Chr(CLng(\"" ascii
		$s5 = "= \"4d5a90000300000004000000ffff00" ascii
		$s6 = "For i = 1 to Len(" ascii
		$s7 = ") Step 2" ascii

	condition:
		5 of them
}
