rule MALPEDIA_Win_Ismagent_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "efc3a6d8-4046-5104-90f5-9440914b7f87"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ismagent"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.ismagent_auto.yar#L1-L102"
		license_url = "N/A"
		logic_hash = "d297d8bd0034edde53a6d3eb1d7bb7add88b3f450af6b836362398a9173b61dc"
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
		$sequence_0 = { ba???????? 6a00 6800000080 6a00 6a00 68???????? 53 }
		$sequence_1 = { 89442440 85c0 752b 50 68???????? }
		$sequence_2 = { eb7c c745e000fe4100 ebbb d9e8 8b4510 }
		$sequence_3 = { e8???????? 83c408 89442418 85c0 0f8479020000 }
		$sequence_4 = { 68e8030000 ff15???????? 8d8c2418030000 8d5101 }
		$sequence_5 = { 7432 8d842418030000 68???????? 50 e8???????? 8bf0 }
		$sequence_6 = { 8bf2 0f1f4000 8a02 42 84c0 75f9 8dbc2400070000 }
		$sequence_7 = { 8d0439 7413 0f1f4000 803823 740a }

	condition:
		7 of them and filesize <327680
}
