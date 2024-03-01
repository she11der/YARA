import "pe"

rule SIGNATURE_BASE_Disclosed_0Day_Pocs_Payload_MSI : FILE
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		author = "Florian Roth (Nextron Systems)"
		id = "fe32af56-d5a1-5246-a7df-395b9cd02faf"
		date = "2017-07-07"
		modified = "2022-12-21"
		reference = "Disclosed 0day Repos"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3747-L3763"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7dfc8d2bd871ad6acb7d362a946d34ed1830f42ab625c3d3d9cb512f28ccdb57"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a7c498a95850e186b7749a96004a98598f45faac2de9b93354ac93e627508a87"

	strings:
		$s1 = "WShell32.dll" fullword wide
		$s2 = "Target empty, so account name translation begins on the local system." fullword wide
		$s3 = "\\custact\\x86\\AICustAct.pdb" ascii

	condition:
		( uint16(0)==0xcfd0 and filesize <1000KB and all of them )
}
