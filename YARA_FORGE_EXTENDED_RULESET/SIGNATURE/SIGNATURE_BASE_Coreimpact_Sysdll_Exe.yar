rule SIGNATURE_BASE_Coreimpact_Sysdll_Exe
{
	meta:
		description = "Detects a malware sysdll.exe from the Rocket Kitten APT"
		author = "Florian Roth (Nextron Systems)"
		id = "bac55c00-5d14-59ca-8597-f52b4577be0c"
		date = "2014-12-27"
		modified = "2023-01-06"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_coreimpact_agent.yar#L6-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f89a4d4ae5cca6d69a5256c96111e707"
		logic_hash = "332b68e797e8ee3e26d797e106ae31e7240585ccb0ea599bebd8ac8f94313eab"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s0 = "d:\\nightly\\sandbox_avg10_vc9_SP1_2011\\source\\avg10\\avg9_all_vs90\\bin\\Rele" ascii
		$s1 = "Mozilla/5.0" fullword ascii
		$s3 = "index.php?c=%s&r=%lx" fullword ascii
		$s4 = "index.php?c=%s&r=%x" fullword ascii
		$s5 = "127.0.0.1" fullword ascii
		$s6 = "/info.dat" ascii
		$s7 = "needroot" fullword ascii
		$s8 = "./plugins/" ascii

	condition:
		$s0 or 6 of them
}
