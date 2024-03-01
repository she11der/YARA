rule MALPEDIA_Win_Darkshell_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "54238af5-7449-55bf-9dc2-08b5916a169b"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkshell"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.darkshell_auto.yar#L1-L122"
		license_url = "N/A"
		logic_hash = "b58c1bc2e0988d2ff26125d2777445ac18dab56ca2991d83e57c5d570ae3c235"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 83c004 8901 83c014 8902 6681380b01 7511 }
		$sequence_1 = { 6a00 6a00 50 53 ffd5 8be8 }
		$sequence_2 = { 7413 8b4c2410 8b54240c 51 52 ffd0 }
		$sequence_3 = { ff542414 53 ff542414 56 ff15???????? }
		$sequence_4 = { 8d542418 6a04 52 684be12200 50 }
		$sequence_5 = { e8???????? 8b4c2414 8bf0 8b442418 6800400000 50 }
		$sequence_6 = { 89442418 ffd7 6a00 6a00 6a00 6a00 }
		$sequence_7 = { 55 ff542424 55 ff542414 53 }
		$sequence_8 = { 8902 6681380b01 7511 8b4c2410 05e0000000 8901 b801000000 }
		$sequence_9 = { ff15???????? 8b542410 8d4c2414 51 6a04 52 }

	condition:
		7 of them and filesize <344064
}
