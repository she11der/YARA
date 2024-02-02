rule BINARYALERT_Hacktool_Windows_Wmi_Implant
{
	meta:
		description = "A PowerShell based tool that is designed to act like a RAT"
		author = "@fusionrace"
		id = "cd90ef31-6e15-5518-8278-98e99e379916"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/windows/hacktool_windows_wmi_implant.yara#L1-L21"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "8b02fd265b04b9675a99b9638fdd179c8a86ed3afd7506195f3d3dcb2417d74d"
		score = 75
		quality = 80
		tags = ""

	strings:
		$s1 = "This really isn't applicable unless you are using WMImplant interactively." fullword ascii wide
		$s2 = "What command do you want to run on the remote system? >" fullword ascii wide
		$s3 = "Do you want to [create] or [delete] a string registry value? >" fullword ascii wide
		$s4 = "Do you want to run a WMImplant against a list of computers from a file? [yes] or [no] >" fullword ascii wide
		$s5 = "What is the name of the service you are targeting? >" fullword ascii wide
		$s6 = "This function enables the user to upload or download files to/from the attacking machine to/from the targeted machine" fullword ascii wide
		$s7 = "gen_cli - Generate the CLI command to execute a command via WMImplant" fullword ascii wide
		$s8 = "exit - Exit WMImplant" fullword ascii wide
		$s9 = "Lateral Movement Facilitation" fullword ascii wide
		$s10 = "vacant_system - Determine if a user is away from the system." fullword ascii wide
		$s11 = "Please provide the ProcessID or ProcessName flag to specify the process to kill!" fullword ascii wide

	condition:
		any of them
}