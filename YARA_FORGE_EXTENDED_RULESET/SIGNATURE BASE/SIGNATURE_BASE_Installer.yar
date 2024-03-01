rule SIGNATURE_BASE_Installer
{
	meta:
		description = "Webshells Auto-generated - file installer.cmd"
		author = "Florian Roth (Nextron Systems)"
		id = "681d8284-55e5-5316-a0d2-f4f13218df76"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7849-L7861"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a507919ae701cf7e42fa441d3ad95f8f"
		logic_hash = "73c1032313155ceb752fe2f94c8d242833127fe0443d7e3044fa1de2b2b7742b"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Restore Old Vanquish"
		$s4 = "ReInstall Vanquish"

	condition:
		all of them
}
