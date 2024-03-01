rule SIGNATURE_BASE_Empire_Keepassconfig : FILE
{
	meta:
		description = "Detects Empire component - file KeePassConfig.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "814a6ff9-a6ac-55e7-bb3f-597351ce421d"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_empire.yar#L337-L350"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "044c8a326ee6cc74a918e6c28100032bfd2fb396ddab8683ab11e00f9370ab2a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"

	strings:
		$s1 = "$UserMasterKeyFiles = @(, $(Get-ChildItem -Path $UserMasterKeyFolder -Force | Select-Object -ExpandProperty FullName) )" fullword ascii

	condition:
		( uint16(0)==0x7223 and filesize <80KB and 1 of them ) or all of them
}
