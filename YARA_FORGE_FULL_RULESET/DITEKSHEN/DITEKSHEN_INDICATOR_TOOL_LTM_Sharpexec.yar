import "pe"

rule DITEKSHEN_INDICATOR_TOOL_LTM_Sharpexec : FILE
{
	meta:
		description = "Detects SharpExec lateral movement tool"
		author = "ditekSHen"
		id = "4373a052-9525-5b24-81a4-65cd68afcb6c"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_tools.yar#L256-L275"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "17ae5c9f0b22e8ecbbbcbe052e466d00cb7b62cff423688b5138209c52f0698d"
		score = 75
		quality = 23
		tags = "FILE"

	strings:
		$s1 = "fileUploaded" fullword ascii
		$s2 = "$7fbad126-e21c-4c4e-a9f0-613fcf585a71" fullword ascii
		$s3 = "DESKTOP_HOOKCONTROL" fullword ascii
		$s4 = /WINSTA_(ACCESSCLIPBOARD|WINSTA_ALL_ACCESS)/ fullword ascii
		$s5 = /NETBIND(ADD|DISABLE|ENABLE|REMOVE)/ fullword ascii
		$s6 = /SERVICE_(ALL_ACCESS|WIN32_OWN_PROCESS|INTERROGATE)/ fullword ascii
		$s7 = /(Sharp|PS|smb)Exec/ fullword ascii
		$s8 = "lpszPassword" fullword ascii
		$s9 = "lpszDomain" fullword ascii
		$s10 = "wmiexec" fullword ascii
		$s11 = "\\C$\\__LegitFile" wide
		$s12 = "LOGON32_LOGON_NEW_CREDENTIALS" fullword ascii

	condition:
		( uint16(0)==0x5a4d and 9 of them ) or ( all of them )
}
