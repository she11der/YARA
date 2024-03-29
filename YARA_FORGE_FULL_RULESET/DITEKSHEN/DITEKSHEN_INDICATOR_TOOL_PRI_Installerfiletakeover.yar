import "pe"

rule DITEKSHEN_INDICATOR_TOOL_PRI_Installerfiletakeover : CVE_2021_41379 FILE
{
	meta:
		description = "Detect InstallerFileTakeOver CVE-2021-41379"
		author = "ditekSHen"
		id = "8581a306-e6d3-5ac1-a778-76c6505ee174"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_tools.yar#L1234-L1253"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "0a9e53138d33494d9b2aa0271b877e405ea2e8accba7c6eeac547caaa7a7c2ea"
		score = 75
		quality = 50
		tags = "CVE-2021-41379, FILE"

	strings:
		$s1 = "splwow64.exe" fullword ascii
		$s2 = "notepad.exe" fullword ascii
		$s3 = "%s\\System32\\cmd.exe" fullword wide
		$s4 = "[SystemFolder]msiexec.exe" fullword wide
		$s5 = "microsoft plz" ascii
		$s6 = "%TEMP%\\" fullword wide
		$x1 = "\\InstallerFileTakeOver.pdb" ascii
		$o1 = { 48 b8 fe ff ff ff ff ff ff 7f 48 8b f5 48 83 ce }
		$o2 = { 4c 8d 62 10 48 c7 c7 ff ff ff ff 48 8b c7 66 0f }
		$o3 = { ff 15 9a 59 00 00 48 8b d8 e8 ba ff ff ff 45 33 }
		$o4 = { 49 c7 43 a8 fe ff ff ff 49 89 5b 10 48 8b 05 5a }
		$o5 = { 66 89 7c 24 50 48 c7 c2 ff ff ff ff 48 ff c2 66 }

	condition:
		uint16(0)==0x5a4d and ((1 of ($x*) and (2 of ($s*) or 3 of ($o*))) or 4 of ($s*) or ( all of ($o*) and 2 of them ))
}
