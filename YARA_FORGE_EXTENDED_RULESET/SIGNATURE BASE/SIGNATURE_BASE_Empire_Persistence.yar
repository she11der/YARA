rule SIGNATURE_BASE_Empire_Persistence : FILE
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Persistence.psm1"
		author = "Florian Roth (Nextron Systems)"
		id = "0f63b5f4-f933-5821-b0b0-50717e75f6d9"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "https://github.com/PowerShellEmpire/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_powershell_empire.yar#L47-L63"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ae8875f7fcb8b4de5cf9721a9f5a9f7782f7c436c86422060ecdc5181e31092f"
		logic_hash = "3c398aa180b6f2225a25f9b1430e89991c7e391930e2be140e89c67da67b3614"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "C:\\PS>Add-Persistence -ScriptBlock $RickRoll -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions -V" ascii
		$s2 = "# Execute the following to remove the user-level persistent payload" fullword ascii
		$s3 = "$PersistantScript = $PersistantScript.ToString().Replace('EXECUTEFUNCTION', \"$PersistenceScriptName -Persist\")" fullword ascii

	condition:
		filesize <108KB and 1 of them
}
