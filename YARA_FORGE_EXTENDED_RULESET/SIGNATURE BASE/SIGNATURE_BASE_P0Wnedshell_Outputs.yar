rule SIGNATURE_BASE_P0Wnedshell_Outputs
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - from files p0wnedShell.cs, p0wnedShell.cs"
		author = "Florian Roth (Nextron Systems)"
		id = "c19fc14b-0c42-5dd1-bff2-ba75f4168d9c"
		date = "2017-01-14"
		modified = "2023-12-05"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_p0wnshell.yar#L180-L196"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "85d5317a473d981fe6ee1362789f34653a838c63d823bb62028a25c9db27cf6e"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"

	strings:
		$s1 = "[+] For this attack to succeed, you need to have Admin privileges." fullword ascii
		$s2 = "[+] This is not a valid hostname, please try again" fullword ascii
		$s3 = "[+] First return the name of our current domain." fullword ascii

	condition:
		1 of them
}
