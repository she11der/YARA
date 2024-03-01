rule SIGNATURE_BASE_P0Wnedlistenerconsole
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedListenerConsole.cs"
		author = "Florian Roth (Nextron Systems)"
		id = "77d13c34-3e15-5bc1-a100-f04be38cfb44"
		date = "2017-01-14"
		modified = "2023-12-05"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_p0wnshell.yar#L120-L140"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "068e590f6f4f99c27814f2bf96d51e1c8c6422afcf8b99bb9f1852216335da7b"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d2d84e65fad966a8556696fdaab5dc8110fc058c9e9caa7ea78aa00921ae3169"

	strings:
		$x1 = "Invoke_ReflectivePEInjection" fullword wide
		$x5 = "p0wnedShell> " fullword wide
		$x6 = "Resources.Get_PassHashes" fullword wide
		$s7 = "Invoke_CredentialsPhish" fullword wide
		$s8 = "Invoke_Shellcode" fullword wide
		$s9 = "Resources.Invoke_TokenManipulation" fullword wide
		$s10 = "Resources.Port_Scan" fullword wide
		$s20 = "Invoke_PowerUp" fullword wide

	condition:
		1 of them
}
