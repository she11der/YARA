import "pe"

rule DITEKSHEN_INDICATOR_TOOL_PET_Sharpsphere : FILE
{
	meta:
		description = "Detects SharpSphere red teamers tool to interact with the guest operating systems of virtual machines managed by vCenter"
		author = "ditekSHen"
		id = "878b5174-2368-5fc8-9573-7b2759cab409"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_tools.yar#L766-L783"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "aae9355fcc7a6b5faf3807c85983032519550e936d5660c823d13731083be512"
		score = 75
		quality = 50
		tags = "FILE"

	strings:
		$s1 = "get_virtualExecUsage" fullword ascii
		$s2 = "Command to execute" fullword ascii
		$s3 = "<guestusername>k__" ascii
		$s4 = ".VirtualMachineDeviceRuntimeInfoVirtualEthernetCardRuntimeState" ascii
		$s5 = "datastoreUrl" ascii
		$s6 = "SharpSphere.vSphere." ascii
		$s7 = "HelpText+vCenter SDK URL, i.e. https://127.0.0.1/sdk" ascii
		$s8 = "[x] Execution finished, attempting to retrieve the results" fullword wide
		$s9 = "C:\\Windows\\System32\\cmd.exe" fullword wide
		$s10 = "C:\\Users\\Public\\" fullword wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}
