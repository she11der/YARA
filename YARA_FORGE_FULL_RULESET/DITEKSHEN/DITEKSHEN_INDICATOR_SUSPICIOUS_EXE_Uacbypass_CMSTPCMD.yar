import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Uacbypass_CMSTPCMD : FILE
{
	meta:
		description = "Detects Windows exceutables bypassing UAC using CMSTP utility, command line and INF"
		author = "ditekSHen"
		id = "7bad57dc-ee8b-559d-8b17-af44c5bdf35b"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1118-L1131"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "4cb92224d5a520dbd42d00d053aba3da21a49fda9391e5a462fd292d2e87e884"
		score = 40
		quality = 41
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "c:\\windows\\system32\\cmstp.exe" ascii wide nocase
		$s2 = "taskkill /IM cmstp.exe /F" ascii wide nocase
		$s3 = "CMSTPBypass" fullword ascii
		$s4 = "CommandToExecute" fullword ascii
		$s5 = "RunPreSetupCommands=RunPreSetupCommandsSection" fullword wide
		$s6 = "\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\", \"ProfileInstallPath\", \"%UnexpectedError%\", \"\"" fullword wide nocase

	condition:
		uint16(0)==0x5a4d and 3 of them
}
