rule SIGNATURE_BASE_Empire_Portscan : FILE
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file portscan.py"
		author = "Florian Roth (Nextron Systems)"
		id = "23a0f769-9155-5aa0-9200-2baf827bdda4"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "https://github.com/PowerShellEmpire/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_empire.yar#L65-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b355efa1e7b3681b1402e22c58ce968795ef245fd08a0afb948d45c173e60b97"
		logic_hash = "162ac4ccc8629a2d017831cdc6d1bf8d7a62b844bf68a0d61956b2f41a5e004b"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "script += \"Invoke-PortScan -noProgressMeter -f\"" fullword ascii
		$s2 = "script += \" | ? {$_.alive}| Select-Object HostName,@{name='OpenPorts';expression={$_.openPorts -join ','}} | ft -wrap | Out-Str" ascii

	condition:
		filesize <14KB and all of them
}
