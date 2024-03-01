rule SIGNATURE_BASE_P0Wnedpotato
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPotato.cs"
		author = "Florian Roth (Nextron Systems)"
		id = "2c2378e3-b948-5325-9afd-76424a7130b1"
		date = "2017-01-14"
		modified = "2023-12-05"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_p0wnshell.yar#L64-L81"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d9107db6c6460429358a2f9f1f47d103e96811152e8d03517871ff0c66578d05"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "aff2b694a01b48ef96c82daf387b25845abbe01073b76316f1aab3142fdb235b"

	strings:
		$x1 = "Invoke-Tater" fullword ascii
		$x2 = "P0wnedListener.Execute(WPAD_Proxy);" fullword ascii
		$x3 = " -SpooferIP " ascii
		$x4 = "TaterCommand()" ascii
		$x5 = "FileName = \"cmd.exe\"," fullword ascii

	condition:
		1 of them
}
