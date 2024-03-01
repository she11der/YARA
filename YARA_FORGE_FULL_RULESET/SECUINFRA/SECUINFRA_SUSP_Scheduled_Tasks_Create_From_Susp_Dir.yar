rule SECUINFRA_SUSP_Scheduled_Tasks_Create_From_Susp_Dir : FILE
{
	meta:
		description = "Detects a PowerShell Script that creates a Scheduled Task that runs from an suspicious directory"
		author = "SECUINFRA Falcon Team"
		id = "65aad597-c5fe-50c3-8970-19fb502f1602"
		date = "2022-02-21"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Windows/windows_misc.yar#L2-L25"
		license_url = "N/A"
		logic_hash = "abe0592a8936898a43a1df9039829948f8a4a425c74cb970d2899d513c9cfffe"
		score = 60
		quality = 25
		tags = "FILE"
		version = "0.1"

	strings:
		$create = "New-ScheduledTaskAction"
		$execute = "-Execute"
		$trigger = "New-ScheduledTaskTrigger"
		$at_param = "-At"
		$register = "Register-ScheduledTask"
		$action = "-Action"
		$path1 = "C:\\ProgramData\\"
		$path2 = "C:\\Windows\\Temp"
		$path3 = "AppData\\Local"

	condition:
		filesize <30KB and 1 of ($path*) and ($create and $execute) or ($trigger and $at_param) or ($register and $action)
}
