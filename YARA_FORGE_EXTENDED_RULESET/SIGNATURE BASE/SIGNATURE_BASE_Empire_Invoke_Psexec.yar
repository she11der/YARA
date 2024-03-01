rule SIGNATURE_BASE_Empire_Invoke_Psexec : FILE
{
	meta:
		description = "Detects Empire component - file Invoke-PsExec.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "19aaec3e-3e8f-5d7d-9c70-a212756c0300"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_empire.yar#L258-L273"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "86af63a3be5b4940966932b129edbe4cca5ac1a31d120ba44fdca739e9c97ad4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0218be4323959fc6379489a6a5e030bb9f1de672326e5e5b8844ab5cedfdcf88"

	strings:
		$s1 = "Invoke-PsExecCmd" fullword ascii
		$s2 = "\"[*] Executing service .EXE" fullword ascii
		$s3 = "$cmd = \"%COMSPEC% /C echo $Command ^> %systemroot%\\Temp\\" ascii

	condition:
		( uint16(0)==0x7566 and filesize <50KB and 1 of them ) or all of them
}
