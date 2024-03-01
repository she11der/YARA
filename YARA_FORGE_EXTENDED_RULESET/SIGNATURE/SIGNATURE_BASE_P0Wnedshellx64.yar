rule SIGNATURE_BASE_P0Wnedshellx64
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedShellx64.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c9791804-4f08-5b7e-8d9d-37e2dfccec47"
		date = "2017-01-14"
		modified = "2021-09-15"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_p0wnshell.yar#L99-L118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d7cd33548ed3485cc6f3cd289813a8eb83b34e800b839c5c8f8add5f9e01a3da"
		score = 75
		quality = 85
		tags = ""
		hash1 = "d8b4f5440627cf70fa0e0e19e0359b59e671885f8c1855517211ba331f48c449"

	strings:
		$x1 = "Oq02AB+LCAAAAAAABADs/QkW3LiOLQBuRUsQR1H731gHMQOkFGFnvvrdp/O4sp6tkDiAIIjhAryu4z6PVOtxHuXz3/xT6X9za/Df/Hsa/JT/9Pjgb/+kPPhv9Sjp01Wf" wide
		$x2 = "Invoke-TokenManipulation" wide
		$x3 = "-CreateProcess \"cmd.exe\" -Username \"nt authority\\system\"" fullword wide
		$x4 = "CommandShell with Local Administrator privileges :)" fullword wide
		$x5 = "Invoke-shellcode -Payload windows/meterpreter/reverse_https -Lhost " fullword wide
		$fp1 = "AVSignature" ascii wide

	condition:
		1 of ($x*) and not 1 of them
}
