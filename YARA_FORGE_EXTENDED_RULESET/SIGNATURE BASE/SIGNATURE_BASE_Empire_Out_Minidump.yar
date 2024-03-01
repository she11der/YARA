rule SIGNATURE_BASE_Empire_Out_Minidump : FILE
{
	meta:
		description = "Detects Empire component - file Out-Minidump.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "8c53d2ab-afc5-5d7b-97e1-496425b9664f"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_empire.yar#L242-L256"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7ce4ac95ac942a2ad758b1d9034e6ec50d25d195ba1c2ae95a90a7490708e485"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7803ae7ba5d4e7d38e73745b3f321c2ca714f3141699d984322fa92e0ff037a1"

	strings:
		$s1 = "$Result = $MiniDumpWriteDump.Invoke($null, @($ProcessHandle," fullword ascii
		$s2 = "$ProcessFileName = \"$($ProcessName)_$($ProcessId).dmp\"" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <10KB and 1 of them ) or all of them
}
