rule SIGNATURE_BASE_Ps1_Toolkit_Invoke_Relfectivepeinjection : FILE
{
	meta:
		description = "Auto-generated rule - file Invoke-RelfectivePEInjection.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "75ceb01e-103f-55b2-8362-42d22a35a36a"
		date = "2016-09-04"
		modified = "2023-12-05"
		reference = "https://github.com/vysec/ps1-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_toolkit.yar#L92-L111"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "910b8b1dbc7306369f90eae0dfd5949347b2c41fa0eb5f590aed8e90e8db199a"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"

	strings:
		$x1 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)" fullword ascii
		$x2 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local" fullword ascii
		$x3 = "} = Get-ProcAddress Advapi32.dll OpenThreadToken" ascii
		$x4 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local" fullword ascii
		$s5 = "$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')" fullword ascii
		$s6 = "= Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" ascii

	condition:
		( uint16(0)==0xbbef and filesize <700KB and 2 of them ) or ( all of them )
}
