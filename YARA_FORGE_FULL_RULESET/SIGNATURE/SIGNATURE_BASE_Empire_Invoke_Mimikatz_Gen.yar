rule SIGNATURE_BASE_Empire_Invoke_Mimikatz_Gen : FILE
{
	meta:
		description = "Detects Empire component - file Invoke-Mimikatz.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "1f771a17-2534-5811-80bd-bc1bab37d97c"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L124-L138"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a28297025b9b0178ab437996ffd3e0c28526f1edaf61db659093fe41a356cf40"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"

	strings:
		$s1 = "= \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQ" ascii
		$s2 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <4000KB and 1 of them ) or all of them
}
