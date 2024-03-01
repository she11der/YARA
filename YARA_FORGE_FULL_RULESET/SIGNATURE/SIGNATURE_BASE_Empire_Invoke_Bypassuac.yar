rule SIGNATURE_BASE_Empire_Invoke_Bypassuac : FILE
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-BypassUAC.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "8454d929-e184-5be1-b61f-4dfa8f44bdda"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "https://github.com/PowerShellEmpire/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_empire.yar#L9-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ab0f900a6915b7497313977871a64c3658f3e6f73f11b03d2d33ca61305dc6a8"
		logic_hash = "1697065405fa0e255cdd77fa39f53866118caf0bad6a3d72756590303610e7b6"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
		$s2 = "$proc = Start-Process -WindowStyle Hidden notepad.exe -PassThru" fullword ascii
		$s3 = "$Payload = Invoke-PatchDll -DllBytes $Payload -FindString \"ExitThread\" -ReplaceString \"ExitProcess\"" fullword ascii
		$s4 = "$temp = [System.Text.Encoding]::UNICODE.GetBytes($szTempDllPath)" fullword ascii

	condition:
		filesize <1200KB and 3 of them
}
