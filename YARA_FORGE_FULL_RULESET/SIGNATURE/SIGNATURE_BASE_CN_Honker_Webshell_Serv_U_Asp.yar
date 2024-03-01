rule SIGNATURE_BASE_CN_Honker_Webshell_Serv_U_Asp : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file Serv-U asp.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "06a58a05-92bd-5124-a172-2bfd9491c2fc"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L441-L457"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "cee91cd462a459d31a95ac08fe80c70d2f9c1611"
		logic_hash = "c98c3f4db5ea812827b6108ef88b57116621142202248f4f26f0c71bd76e33ec"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii
		$s2 = "<td><input name=\"c\" type=\"text\" id=\"c\" value=\"cmd /c net user goldsun lov" ascii
		$s3 = "deldomain = \"-DELETEDOMAIN\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \" PortNo=\"" ascii

	condition:
		filesize <30KB and 2 of them
}
