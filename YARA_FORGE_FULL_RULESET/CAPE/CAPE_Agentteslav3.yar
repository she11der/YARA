rule CAPE_Agentteslav3 : FILE
{
	meta:
		description = "AgentTeslaV3 infostealer payload"
		author = "ditekshen"
		id = "cfe00382-8663-54a4-a7c4-b932ec7ad5e3"
		date = "2023-10-31"
		modified = "2023-10-31"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/AgentTesla.yar#L69-L111"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		logic_hash = "26c4fa0ce8de6982eb599f3872e8ab2a6e83da4741db7f3500c94e0a8fe5d459"
		score = 75
		quality = 68
		tags = "FILE"
		cape_type = "AgentTesla payload"

	strings:
		$s1 = "get_kbok" fullword ascii
		$s2 = "get_CHoo" fullword ascii
		$s3 = "set_passwordIsSet" fullword ascii
		$s4 = "get_enableLog" fullword ascii
		$s5 = "bot%telegramapi%" wide
		$s6 = "KillTorProcess" fullword ascii
		$s7 = "GetMozilla" ascii
		$s8 = "torbrowser" wide
		$s9 = "%chatid%" wide
		$s10 = "logins" fullword wide
		$s11 = "credential" fullword wide
		$s12 = "AccountConfiguration+" wide
		$s13 = "<a.+?href\\s*=\\s*([\"'])(?<href>.+?)\\1[^>]*>" fullword wide
		$s14 = "set_Lenght" fullword ascii
		$s15 = "get_Keys" fullword ascii
		$s16 = "set_AllowAutoRedirect" fullword ascii
		$s17 = "set_wtqQe" fullword ascii
		$s18 = "set_UseShellExecute" fullword ascii
		$s19 = "set_IsBodyHtml" fullword ascii
		$s20 = "set_FElvMn" fullword ascii
		$s21 = "set_RedirectStandardOutput" fullword ascii
		$g1 = "get_Clipboard" fullword ascii
		$g2 = "get_Keyboard" fullword ascii
		$g3 = "get_Password" fullword ascii
		$g4 = "get_CtrlKeyDown" fullword ascii
		$g5 = "get_ShiftKeyDown" fullword ascii
		$g6 = "get_AltKeyDown" fullword ascii
		$m1 = "yyyy-MM-dd hh-mm-ssCookieapplication/zipSCSC_.jpegScreenshotimage/jpeg/log.tmpKLKL_.html<html></html>Logtext/html[]Time" ascii
		$m2 = "%image/jpg:Zone.Identifier\\tmpG.tmp%urlkey%-f \\Data\\Tor\\torrcp=%PostURL%127.0.0.1POST+%2B" ascii
		$m3 = ">{CTRL}</font>Windows RDPcredentialpolicyblobrdgchrome{{{0}}}CopyToComputeHashsha512CopySystemDrive\\WScript.ShellRegReadg401" ascii
		$m4 = "%startupfolder%\\%insfolder%\\%insname%/\\%insfolder%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%insregname%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\RunTruehttp" ascii
		$m5 = "\\WindowsLoad%ftphost%/%ftpuser%%ftppassword%STORLengthWriteCloseGetBytesOpera" ascii

	condition:
		( uint16(0)==0x5a4d and (8 of ($s*) or (6 of ($s*) and 4 of ($g*)))) or (2 of ($m*))
}
