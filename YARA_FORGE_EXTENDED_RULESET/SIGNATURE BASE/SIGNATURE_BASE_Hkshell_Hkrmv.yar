rule SIGNATURE_BASE_Hkshell_Hkrmv
{
	meta:
		description = "Webshells Auto-generated - file hkrmv.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "986fad12-9198-5e0a-88d6-a9be6963ff8c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7648-L7660"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "bd3a0b7a6b5536f8d96f50956560e9bf"
		logic_hash = "f1da0778456272e6d93633a564018bdf0fa74f1db1c9e963a03a59c69c752b6e"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "/THUMBPOSITION7"
		$s6 = "\\EvilBlade\\"

	condition:
		all of them
}
