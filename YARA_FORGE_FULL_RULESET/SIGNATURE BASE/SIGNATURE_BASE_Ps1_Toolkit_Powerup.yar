rule SIGNATURE_BASE_Ps1_Toolkit_Powerup : FILE
{
	meta:
		description = "Auto-generated rule - file PowerUp.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "ff3eeec3-602d-5824-8a50-aed2081f49bc"
		date = "2016-09-04"
		modified = "2023-12-05"
		reference = "https://github.com/vysec/ps1-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_toolkit.yar#L10-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "64562c623de89df59d15db48990c25886c67b79ac9341cf8f21ef372057ccd85"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fc65ec85dbcd49001e6037de9134086dd5559ac41ac4d1adf7cab319546758ad"

	strings:
		$s1 = "iex \"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe list vdir /text:vdir.name\" | % { " fullword ascii
		$s2 = "iex \"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe list apppools /text:name\" | % { " fullword ascii
		$s3 = "if ($Env:PROCESSOR_ARCHITECTURE -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBNAEQANgA0AA==')))) {" fullword ascii
		$s4 = "C:\\Windows\\System32\\InetSRV\\appcmd.exe list vdir /text:physicalpath | " fullword ascii
		$s5 = "if (Test-Path  (\"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe\"))" fullword ascii
		$s6 = "if (Test-Path  (\"$Env:SystemRoot\\System32\\InetSRV\\appcmd.exe\")) {" fullword ascii
		$s7 = "Write-Verbose \"Executing command '$Cmd'\"" fullword ascii
		$s8 = "Write-Warning \"[!] Target service" fullword ascii

	condition:
		( uint16(0)==0xbbef and filesize <4000KB and 1 of them ) or (3 of them )
}
