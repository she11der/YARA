rule SIGNATURE_BASE_Win_Privesc_Folderperm
{
	meta:
		description = "Detects a tool that can be used for privilege escalation - file folderperm.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "131fdb57-f9ca-5247-8bb4-c939eff5b8bf"
		date = "2016-06-02"
		modified = "2023-12-05"
		reference = "http://www.greyhathacker.net/?p=738"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_win_privesc.yar#L28-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "899fda75e4c6d9f588767e5170dbd30241a492ba89f7cc1b0ad4adb2fcd173cb"
		score = 80
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1aa87df34826b1081c40bb4b702750587b32d717ea6df3c29715eb7fc04db755"

	strings:
		$x1 = "# powershell.exe -executionpolicy bypass -file folderperm.ps1" fullword ascii
		$x2 = "Write-Host \"[i] Dummy test file used to test access was not outputted:\" $filetocopy" fullword ascii
		$x3 = "Write-Host -foregroundColor Red \"      Access denied :\" $myarray[$i] " fullword ascii

	condition:
		1 of them
}
