rule SIGNATURE_BASE_Empire_Invoke_Metasploitpayload : FILE
{
	meta:
		description = "Detects Empire component - file Invoke-MetasploitPayload.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "608c30b0-826a-55b1-afb8-756b476d6b55"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L10-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1399818f71544245a7b689a7eb4da794b10814590e4c5f545fc28237ffa3d0f6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a85ca27537ebeb79601b885b35ddff6431860b5852c6a664d32a321782808c54"

	strings:
		$s1 = "$ProcessInfo.Arguments=\"-nop -c $DownloadCradle\"" fullword ascii
		$s2 = "$PowershellExe=$env:windir+'\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe'" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <9KB and 1 of them ) or all of them
}
