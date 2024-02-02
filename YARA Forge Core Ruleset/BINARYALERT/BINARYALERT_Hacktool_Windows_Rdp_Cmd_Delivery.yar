rule BINARYALERT_Hacktool_Windows_Rdp_Cmd_Delivery
{
	meta:
		description = "Delivers a text payload via RDP (rubber ducky)"
		author = "@fusionrace"
		id = "8d035721-34ee-566f-8851-1c9501de2704"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://github.com/nopernik/mytools/blob/master/rdp-cmd-delivery.sh"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/windows/hacktool_windows_rdp_cmd_delivery.yara#L1-L14"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "98bc02bb651fba069828b5960ee47542828f0d530e5e280b15abb0573b8e0168"
		score = 75
		quality = 80
		tags = ""

	strings:
		$s1 = "Usage: rdp-cmd-delivery.sh OPTIONS" ascii wide
		$s2 = "[--tofile 'c:\\test.txt' local.ps1 #will copy contents of local.ps1 to c:\\test.txt" ascii wide
		$s3 = "-cmdfile local.bat                #will execute everything from local.bat" ascii wide
		$s4 = "To deliver powershell payload, use '--cmdfile script.ps1' but inside powershell console" ascii wide

	condition:
		any of them
}