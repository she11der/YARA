rule SIGNATURE_BASE_Stuxnet_Shortcut_To : FILE
{
	meta:
		description = "Stuxnet Sample - file Copy of Shortcut to.lnk"
		author = "Florian Roth (Nextron Systems)"
		id = "582ab12b-808e-5d5c-ba36-3bb987c4c552"
		date = "2016-07-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_stuxnet.yar#L74-L87"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "a8119500d38bcfc60620265386f31899e586f62e1ceeeff365fd0018ab39c30e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "801e3b6d84862163a735502f93b9663be53ccbdd7f12b0707336fecba3a829a2"

	strings:
		$x1 = "\\\\.\\STORAGE#Volume#_??_USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_PMAP#5B6B098B97BE&0#{53f56307-b6bf-11d0-94f2-00a0c" wide

	condition:
		uint16(0)==0x004c and filesize <10KB and $x1
}
