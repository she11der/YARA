rule SIGNATURE_BASE_Msfpayloads_Msf_11
{
	meta:
		description = "Metasploit Payloads - file msf.hta"
		author = "Florian Roth (Nextron Systems)"
		id = "59b0cced-ffdc-5f2f-878c-856883ee275f"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_metasploit_payloads.yar#L287-L302"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f003989a99315b42c0c73beaa2928d0187fe92a4bf329912d64fac9f8fc9358c"
		score = 75
		quality = 83
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d1daf7bc41580322333a893133d103f7d67f5cd8a3e0f919471061d41cf710b6"

	strings:
		$s1 = ".ExpandEnvironmentStrings(\"%PSModulePath%\") + \"..\\powershell.exe\") Then" fullword ascii
		$s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
		$s3 = "= CreateObject(\"Wscript.Shell\") " fullword ascii

	condition:
		all of them
}
