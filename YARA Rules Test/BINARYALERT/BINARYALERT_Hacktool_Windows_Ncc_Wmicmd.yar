rule BINARYALERT_Hacktool_Windows_Ncc_Wmicmd
{
	meta:
		description = "Command shell wrapper for WMI"
		author = "@mimeframe"
		id = "18bc36f7-b97a-5bce-a68b-c349713e9468"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://github.com/nccgroup/WMIcmd"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/windows/hacktool_windows_ncc_wmicmd.yara#L1-L18"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "bef6828a706dcfc3b573523fccd391a5ef3fa505235b1621a82527d64d32aaf0"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "Need to specify a username, domain and password for non local connections" wide ascii
		$a2 = "WS-Management is running on the remote host" wide ascii
		$a3 = "firewall (if enabled) allows connections" wide ascii
		$a4 = "WARNING: Didn't see stdout output finished marker - output may be truncated" wide ascii
		$a5 = "Command sleep in milliseconds - increase if getting truncated output" wide ascii
		$b1 = "0x800706BA" wide ascii
		$b2 = "NTLMDOMAIN:" wide ascii
		$b3 = "cimv2" wide ascii

	condition:
		any of ($a*) or all of ($b*)
}