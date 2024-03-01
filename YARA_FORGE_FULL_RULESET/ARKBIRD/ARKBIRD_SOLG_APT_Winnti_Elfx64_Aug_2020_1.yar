rule ARKBIRD_SOLG_APT_Winnti_Elfx64_Aug_2020_1 : FILE
{
	meta:
		description = "Detect of ELF implant used by APT Winnti in August 2020"
		author = "Arkbird_SOLG"
		id = "112e8d60-cbcb-53a7-b458-d39ee03d5c22"
		date = "2020-08-18"
		modified = "2020-08-18"
		reference = "https://twitter.com/KorbenD_Intel/status/1295725146037133312"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-08-18/Winnti/APT_Winnti_ELFx64_Aug_2020_1.yar#L1-L34"
		license_url = "N/A"
		logic_hash = "ebe6e60c45336476fd91c4185eee0414c3eba83960301a610b69c8818dbb17fd"
		score = 75
		quality = 36
		tags = "FILE"
		hash1 = "6af8b3d31101f48911b13e49c660c10ed1d26b60267e8037d2ac174fc0d2f36c"

	strings:
		$lib1 = "/usr/bin/python2.7" fullword ascii
		$lib2 = "libxselinux" fullword ascii
		$c1 = "/cmdlineH" fullword ascii
		$c2 = "/proc/%d/fd/%s" fullword ascii
		$c3 = "/proc/self/exe" fullword ascii
		$c4 = "__gmon_start__" fullword ascii
		$c5 = "_ITM_registerTMCloneTable" fullword ascii
		$c6 = "_ITM_deregisterTMCloneTable" fullword ascii
		$d1 = "/usr/bin/netstat" fullword ascii
		$d2 = "/var/run/libudev.pid" fullword ascii
		$d3 = "/sbin/ifup-local" fullword ascii
		$s1 = "EAEC2CA4-AF8D-4F61-8115-9EC26F6BF4E1" fullword ascii
		$s2 = "readdir64" fullword ascii
		$s3 = ".note.gnu.gold-version" fullword ascii
		$s4 = ".note.gnu.build-id" fullword ascii
		$s5 = ".eh_frame_hdr" fullword ascii
		$s6 = "xlstat" fullword ascii
		$s7 = "1YZ[\\<@nYSLRR]H_PGX[XmYXGFrstuvwxyz{|}~" fullword ascii
		$info1 = "check_is_our_proc_dir" fullword ascii
		$info2 = "get_our_sockets" fullword ascii
		$info3 = "is_invisible_with_pids" fullword ascii
		$info4 = "check_if_number" fullword ascii
		$info5 = "get_our_pids" fullword ascii

	condition:
		uint16(0)==0x457f and filesize <15KB and (1 of ($lib*) and 4 of ($c*) and 2 of ($d*) and 4 of ($s*) and 3 of ($info*))
}
