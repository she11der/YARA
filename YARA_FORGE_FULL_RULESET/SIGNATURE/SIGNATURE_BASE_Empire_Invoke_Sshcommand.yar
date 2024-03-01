rule SIGNATURE_BASE_Empire_Invoke_Sshcommand : FILE
{
	meta:
		description = "Detects Empire component - file Invoke-SSHCommand.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "b06b507f-b6b8-5f4b-8d6d-920f141e9ac1"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L352-L367"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3749c3d58335cb08bff66fe3126fc4977261576a9fbedbd7da673e3921364850"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "cbaf086b14d5bb6a756cbda42943d4d7ef97f8277164ce1f7dd0a1843e9aa242"

	strings:
		$s1 = "$Base64 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA" ascii
		$s2 = "Invoke-SSHCommand -ip 192.168.1.100 -Username root -Password test -Command \"id\"" fullword ascii
		$s3 = "Write-Verbose \"[*] Error loading dll\"" fullword ascii

	condition:
		( uint16(0)==0x660a and filesize <2000KB and 1 of them ) or all of them
}
