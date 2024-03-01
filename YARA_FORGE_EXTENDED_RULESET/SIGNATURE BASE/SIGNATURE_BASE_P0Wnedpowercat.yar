rule SIGNATURE_BASE_P0Wnedpowercat : FILE
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPowerCat.cs"
		author = "Florian Roth (Nextron Systems)"
		id = "059a8e58-7b7e-582e-ba4a-80e4dffe9b5e"
		date = "2017-01-14"
		modified = "2023-12-05"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_p0wnshell.yar#L10-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5882d0f91f237d2abe1149421db0e217e6dfcca70130d346a70d5c851eca085f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6a3ba991d3b5d127c4325bc194b3241dde5b3a5853b78b4df1bce7cbe87c0fdf"

	strings:
		$x1 = "Now if we point Firefox to http://127.0.0.1" fullword ascii
		$x2 = "powercat -l -v -p" fullword ascii
		$x3 = "P0wnedListener" fullword ascii
		$x4 = "EncodedPayload.bat" fullword ascii
		$x5 = "powercat -c " fullword ascii
		$x6 = "Program.P0wnedPath()" ascii
		$x7 = "Invoke-PowerShellTcpOneLine" fullword ascii

	condition:
		( uint16(0)==0x7375 and filesize <150KB and 1 of them ) or (2 of them )
}
