import "pe"

rule ESET_IIS_Group12
{
	meta:
		description = "Detects Group 12 native IIS malware family"
		author = "ESET Research"
		id = "7278f2df-d18a-5d95-9c21-37906629a7f0"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/badiis/badiis.yar#L457-L495"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "8da03328e3702aff8ea5de77fc220f326030c31972d27c0bd9b5918dca550aba"
		score = 75
		quality = 78
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "C:\\inetpub\\temp\\IIS Temporary Compressed Files\\"
		$s2 = "F5XFFHttpModule.dll"
		$s3 = "gtest_redir"
		$s4 = "\\cmd.exe" nocase
		$s5 = "iuuq;00"
		$s6 = "?xhost="
		$s7 = "&reurl="
		$s8 = "?jump=1"
		$s9 = "app|zqb"
		$s10 = "ifeng|ivc|sogou|so.com|baidu|google|youdao|yahoo|bing|118114|biso|gougou|sooule|360|sm|uc"
		$s11 = "sogou|so.com|baidu|google|youdao|yahoo|bing|gougou|sooule|360|sm.cn|uc"
		$s12 = "Hotcss/|Hotjs/"
		$s13 = "HotImg/|HotPic/"
		$s14 = "msf connect error !!"
		$s15 = "download ok !!"
		$s16 = "download error !! "
		$s17 = "param error !!"
		$s18 = "Real Path: "
		$s19 = "unknown cmd !"
		$b1 = {15 BD 01 2E [-] 5E 40 08 97 [-] CF 8C BE 30 [-] 28 42 C6 3B}
		$b2 = {E1 0A DC 39 [-] 49 BA 59 AB [-] BE 56 E0 57 [-] F2 0F 88 3E}

	condition:
		ESET_IIS_Native_Module_PRIVATE and 5 of them
}
