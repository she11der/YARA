rule SIGNATURE_BASE_Empire_Write_Hijackdll : FILE
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Write-HijackDll.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "6a80af21-fb01-5996-b14d-44ff55b7fb3e"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "https://github.com/PowerShellEmpire/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_empire.yar#L135-L151"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "155fa7168e28f15bb34f67344f47234a866e2c63b3303422ff977540623c70bf"
		logic_hash = "e01157fe4adaf647474292bfbbb8196c0b7e89433da52a386a8d9573ae543679"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$DllBytes = Invoke-PatchDll -DllBytes $DllBytes -FindString \"debug.bat\" -ReplaceString $BatchPath" fullword ascii
		$s2 = "$DllBytes32 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAA4fug4AtAnNIbgBTM0hVGhpcyBw" ascii
		$s3 = "[Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes32)" fullword ascii

	condition:
		filesize <500KB and 2 of them
}
