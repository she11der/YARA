import "pe"

rule SIGNATURE_BASE_Jc_ALL_Wineggdropshell_Rar_Folder_Install_2
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Install.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "ebfc8e53-328c-5deb-bf9b-e0270f171c68"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2200-L2218"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "95866e917f699ee74d4735300568640ea1a05afd"
		logic_hash = "9c12e8491918a656e37b4ee6c3a42ec970cb6cf101ca5fe3fdfe9eab16526219"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "http://go.163.com/sdemo" fullword wide
		$s2 = "Player.tmp" fullword ascii
		$s3 = "Player.EXE" fullword wide
		$s4 = "mailto:sdemo@263.net" fullword ascii
		$s5 = "S-Player.exe" fullword ascii
		$s9 = "http://www.BaiXue.net (" wide

	condition:
		all of them
}
