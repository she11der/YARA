rule SIGNATURE_BASE_P0Wnedamsibypass
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedAmsiBypass.cs"
		author = "Florian Roth (Nextron Systems)"
		id = "168af265-d3e9-59a2-b754-20d6c9a298b1"
		date = "2017-01-14"
		modified = "2023-12-05"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_p0wnshell.yar#L163-L178"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1f7613506058706fc74979fdd4f9e425e9d16527120e0f2f49bc21e3e43d3b16"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "345e8e6f38b2914f4533c4c16421d372d61564a4275537e674a2ac3360b19284"

	strings:
		$x1 = "Program.P0wnedPath()" fullword ascii
		$x2 = "namespace p0wnedShell" fullword ascii
		$x3 = "H4sIAAAAAAAEAO1YfXRUx3WflXalFazQgiVb5nMVryzxIbGrt/rcFRZIa1CQYEFCQnxotUhP2pX3Q337HpYotCKrPdbmoQQnkOY0+BQCNKRpe" ascii

	condition:
		1 of them
}
