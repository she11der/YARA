rule TRELLIX_ARC_Rovnix_Downloader : DOWNLOADER
{
	meta:
		description = "Rovnix downloader with sinkhole checks"
		author = "Intel Security"
		id = "d51f8f73-7a3a-5ccf-9122-86061b5399f1"
		date = "2024-02-01"
		modified = "2020-08-14"
		reference = "https://blogs.mcafee.com/mcafee-labs/rovnix-downloader-sinkhole-time-checks/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_Rovnix.yar#L1-L38"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "52cde40c95436129b7d48b4bd5e78b66deb84fdc84a76cc9ac72f24e0777e540"
		score = 75
		quality = 43
		tags = "DOWNLOADER"
		malware_type = "downloader"
		malware_family = "Downloader:W32/Rovnix"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$sink1 = "control"
		$sink2 = "sink"
		$sink3 = "hole"
		$sink4 = "dynadot"
		$sink5 = "block"
		$sink6 = "malw"
		$sink7 = "anti"
		$sink8 = "googl"
		$sink9 = "hack"
		$sink10 = "trojan"
		$sink11 = "abuse"
		$sink12 = "virus"
		$sink13 = "black"
		$sink14 = "spam"
		$boot = "BOOTKIT_DLL.dll"
		$mz = { 4D 5A }

	condition:
		$mz in (0..2) and all of ($sink*) and $boot
}
