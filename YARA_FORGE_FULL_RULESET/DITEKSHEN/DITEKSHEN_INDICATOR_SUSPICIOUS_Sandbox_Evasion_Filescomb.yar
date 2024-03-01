import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_Sandbox_Evasion_Filescomb : FILE
{
	meta:
		description = "Detects executables referencing specific set of files observed in sandob anti-evation, and Emotet"
		author = "ditekSHen"
		id = "04108277-03ac-5479-ac9f-0c7377dc70b8"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1692-L1709"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "d9f235e212e75cef51e3321f49968c75523304dc94a2b7cf3965c9f88d039b43"
		score = 40
		quality = 23
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "c:\\take_screenshot.ps1" ascii wide nocase
		$s2 = "c:\\loaddll.exe" ascii wide nocase
		$s3 = "c:\\email.doc" ascii wide nocase
		$s4 = "c:\\email.htm" ascii wide nocase
		$s5 = "c:\\123\\email.doc" ascii wide nocase
		$s6 = "c:\\123\\email.docx" ascii wide nocase
		$s7 = "c:\\a\\foobar.bmp" ascii wide nocase
		$s8 = "c:\\a\\foobar.doc" ascii wide nocase
		$s9 = "c:\\a\\foobar.gif" ascii wide nocase
		$s10 = "c:\\symbols\\aagmmc.pdb" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 6 of them
}
