rule SIGNATURE_BASE_Debug_Bdoor
{
	meta:
		description = "Webshells Auto-generated - file BDoor.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "0938efe7-2b6d-5749-af9a-967cca85defb"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7160-L7172"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e4e8e31dd44beb9320922c5f49739955"
		logic_hash = "ed8caeb96a6fc48fe23d5db078bbb8ba5aec3c5d4ee382cbc6bc4e01630f1460"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\BDoor\\"
		$s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

	condition:
		all of them
}
