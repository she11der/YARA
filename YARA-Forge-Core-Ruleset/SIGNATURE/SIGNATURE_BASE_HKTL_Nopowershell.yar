rule SIGNATURE_BASE_HKTL_Nopowershell
{
	meta:
		description = "Detects NoPowerShell hack tool"
		author = "Florian Roth (Nextron Systems)"
		id = "17d508d5-833f-5232-a071-dbed8758493b"
		date = "2018-12-28"
		modified = "2022-12-21"
		reference = "https://github.com/bitsadmin/nopowershell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L4586-L4603"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "2207af9fcc61d547dfeff347a1eae2c59024a7270d1b8cbb7abef56d80864728"
		score = 75
		quality = 85
		tags = ""
		hash1 = "2dad091dd00625762a7590ce16c3492cbaeb756ad0e31352a42751deb7cf9e70"

	strings:
		$x1 = "\\NoPowerShell.pdb" ascii
		$x2 = "Invoke-WmiMethod -Class Win32_Process -Name Create \"cmd" fullword wide
		$x3 = "ls C:\\Windows\\System32 -Include *.exe | select -First 10 Name,Length" fullword wide
		$x4 = "ls -Recurse -Force C:\\Users\\ -Include *.kdbx" fullword wide
		$x5 = "NoPowerShell.exe" fullword wide

	condition:
		1 of them
}