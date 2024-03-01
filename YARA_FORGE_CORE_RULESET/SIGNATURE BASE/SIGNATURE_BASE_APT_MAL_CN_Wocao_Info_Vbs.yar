rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Info_Vbs
{
	meta:
		description = "Strings from the information grabber VBS"
		author = "Fox-IT SRT"
		id = "b719fb31-2836-5faf-a7c8-c361a14df2be"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_wocao.yar#L297-L316"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e37f8768c7920b8c3d9fdd6bb3a4e748c47a6c06a8aaed01655355ef3d8c3457"
		score = 75
		quality = 85
		tags = ""

	strings:
		$ = "Logger PingConnect"
		$ = "Logger GetAdmins"
		$ = "Logger InstallPro"
		$ = "Logger Exec"
		$ = "retstr = adminsName & \" Members\" & vbCrLf & _"
		$ = "Logger VolumeName & \" (\" & objDrive.DriveLetter & \":)\" _"
		$ = "txtRes = txtRes & machine & \" can"
		$ = "retstr = \"PID   SID Image Name\" & vbCrLf & \"===="

	condition:
		4 of them
}
